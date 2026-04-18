#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# mac_vlan_audit.pl - MAC Address Table Analysis per VLAN
#
# Purpose:
#   Connects to a Cisco IOS/IOS-XE switch and cross-references the VLAN
#   database against the MAC address table to identify active vs unused VLANs.
#   Useful for VLAN cleanup initiatives, capacity planning, and documentation.
#
# Usage:
#   ./mac_vlan_audit.pl --host <ip> --user <username> --pass <password>
#   ./mac_vlan_audit.pl --host <ip> --user <username> --pass <password> --log audit.log
#   ./mac_vlan_audit.pl --file devices.txt --user <username> --pass <password>
#
# Prerequisites:
#   - Perl modules: Net::SSH::Expect, Getopt::Long
#     Install: cpan Net::SSH::Expect
#   - SSH must be enabled on target device
#   - User account needs at minimum privilege 1 (show commands)
#
# Output:
#   Per-VLAN summary showing VLAN ID, name, state, and MAC count.
#   Flags VLANs with zero MACs as candidates for decommission review.
#
# Tested on: Cisco IOS 15.x, IOS-XE 16.x/17.x
# =============================================================================

my ($host, $user, $pass, $logfile, $device_file, $timeout);
$timeout = 30;

GetOptions(
    'host=s'    => \$host,
    'user=s'    => \$user,
    'pass=s'    => \$pass,
    'log=s'     => \$logfile,
    'file=s'    => \$device_file,
    'timeout=i' => \$timeout,
) or die "Usage: $0 --host <ip> --user <u> --pass <p> [--log file] [--file devices.txt]\n";

die "Must supply --user and --pass\n" unless $user && $pass;
die "Must supply --host or --file\n" unless $host || $device_file;

my @hosts;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; push @hosts, $_ if /\S/ && !/^#/; }
    close $fh;
} else {
    @hosts = ($host);
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log $logfile: $!\n";
}

sub log_output {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my $target = shift;
    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);

    log_output("\n" . "=" x 60 . "\n");
    log_output("Device : $target\n");
    log_output("Time   : $timestamp\n");
    log_output("=" x 60 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $target,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    eval {
        my $login = $ssh->login();
        die "Authentication failed for $target\n" unless $login =~ /[#>]/;
    };
    if ($@) {
        log_output("ERROR: Cannot connect to $target: $@\n");
        return;
    }

    # Disable paging
    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\s*#', $timeout) or do {
        log_output("ERROR: Prompt not found after terminal length on $target\n");
        return;
    };

    # Collect VLAN database
    $ssh->send("show vlan brief\n");
    my $vlan_output = $ssh->waitfor('\s*#', $timeout) or do {
        log_output("ERROR: Timeout getting VLAN data from $target\n");
        return;
    };

    # Collect MAC address table counts per VLAN
    $ssh->send("show mac address-table count\n");
    my $mac_output = $ssh->waitfor('\s*#', $timeout) or do {
        log_output("ERROR: Timeout getting MAC table from $target\n");
        return;
    };

    $ssh->send("exit\n");

    # Parse VLAN brief: lines like "10   management               active    Gi0/1"
    my %vlans;
    for my $line (split /\n/, $vlan_output) {
        if ($line =~ /^(\d+)\s+(\S+)\s+(active|act\/unsup|suspended|act\/lshut)\s*(.*)/) {
            $vlans{$1} = { name => $2, state => $3, ports => $4 };
        }
    }

    # Parse MAC count output: lines like "Vlan 10   : 14"
    my %mac_counts;
    for my $line (split /\n/, $mac_output) {
        if ($line =~ /[Vv]lan\s+(\d+)\s*:\s*(\d+)/) {
            $mac_counts{$1} = $2;
        }
    }

    # Report
    my (@empty_vlans, @active_vlans);
    log_output(sprintf("%-6s %-24s %-12s %s\n", "VLAN", "Name", "State", "MACs"));
    log_output("-" x 55 . "\n");

    for my $vid (sort { $a <=> $b } keys %vlans) {
        next if $vid == 1;  # Skip VLAN 1 — expected to exist everywhere
        my $count = $mac_counts{$vid} // 0;
        my $flag  = ($count == 0) ? " *" : "";
        log_output(sprintf("%-6s %-24s %-12s %d%s\n",
            $vid, $vlans{$vid}{name}, $vlans{$vid}{state}, $count, $flag));
        if ($count == 0) { push @empty_vlans, $vid; }
        else             { push @active_vlans, $vid; }
    }

    log_output("\nSummary for $target:\n");
    log_output("  Total VLANs (excl. VLAN 1) : " . scalar(keys %vlans) . "\n");
    log_output("  Active (MACs > 0)           : " . scalar(@active_vlans) . "\n");
    log_output("  Empty  (MACs = 0) *         : " . scalar(@empty_vlans) . "\n");
    if (@empty_vlans) {
        log_output("  Empty VLAN IDs              : " . join(", ", @empty_vlans) . "\n");
        log_output("  NOTE: Verify empty VLANs before decommission.\n");
        log_output("        MACs flush after 300s; check during business hours.\n");
    }
}

audit_device($_) for @hosts;
close $log_fh if $log_fh;