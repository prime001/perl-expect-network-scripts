#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# stp_audit.pl - Spanning Tree Protocol Port State Auditor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches and audits STP state across all
#   VLANs. Reports root bridge status, topology change counts, ports in
#   non-forwarding states, and flags potential STP instability.
#
# Usage:
#   stp_audit.pl --host <ip|hostname> [--user <user>] [--pass <pass>]
#                [--file <device_list>] [--log <logfile>]
#
# Prerequisites:
#   - Perl modules: Net::SSH::Expect, Getopt::Long
#   - SSH access to target device(s)
#   - Read-only or higher privilege (no enable needed for show commands)
#
# Examples:
#   stp_audit.pl --host 10.0.0.1 --user admin --pass secret
#   stp_audit.pl --file switches.txt --log stp_audit.log
# =============================================================================

my ($host, $user, $pass, $device_file, $log_file);
$user = 'admin';
$pass = 'cisco';

GetOptions(
    'host=s' => \$host,
    'user=s' => \$user,
    'pass=s' => \$pass,
    'file=s' => \$device_file,
    'log=s'  => \$log_file,
) or die "Usage: $0 --host <host> | --file <file> [--user <u>] [--pass <p>] [--log <file>]\n";

die "Specify --host or --file\n" unless $host || $device_file;

my @devices;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; push @devices, $_ if /\S/ && !/^#/; }
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub log_output {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my $target = shift;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    log_output("=" x 60 . "\n");
    log_output("Host: $target  Time: $ts\n");
    log_output("=" x 60 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $target,
        user        => $user,
        password    => $pass,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        timeout     => 15,
        raw_pty     => 1,
    );

    my $login = eval { $ssh->login() };
    if ($@ || !$login || $login =~ /[Pp]ermission|[Dd]enied|[Ee]rror/) {
        log_output("  ERROR: Authentication failed for $target\n\n");
        return;
    }

    # Disable paging
    $ssh->exec('terminal length 0');

    # Check STP summary
    my $summary = $ssh->exec('show spanning-tree summary');
    if (!$summary || $summary =~ /Invalid|Error/) {
        log_output("  ERROR: Could not retrieve STP data\n\n");
        $ssh->close();
        return;
    }

    my ($root_count, $fwd_count, $blk_count, $tc_count) = (0, 0, 0, 0);
    if ($summary =~ /(\d+)\s+vlans\s+are\s+spanning\s+tree\s+enabled/i) {
        log_output("  STP-enabled VLANs: $1\n");
    }
    $root_count++ while $summary =~ /\broot\b/gi;
    if ($summary =~ /Topology\s+change\s+flag.*?(\d+)/i) {
        log_output("  Topology changes detected: $1\n");
    }

    # Per-VLAN root bridge and non-forwarding ports
    my $detail = $ssh->exec('show spanning-tree detail');
    my %vlan_state;
    while ($detail =~ /VLAN(\d+).*?This bridge is (?:the )?root/gi) {
        $vlan_state{$1}{is_root} = 1;
        $root_count++;
    }
    my @blocked;
    while ($detail =~ /((?:Gi|Fa|Te|Eth|Po)\S+)\s+is\s+(Blocking|Listening|Learning)/gi) {
        push @blocked, "$1 ($2)";
    }

    log_output("  VLANs where this switch is root: $root_count\n");
    if (@blocked) {
        log_output("  Non-forwarding ports (" . scalar(@blocked) . "):\n");
        log_output("    - $_\n") for @blocked;
    } else {
        log_output("  Non-forwarding ports: none\n");
    }

    # Flag instability via topology change counter
    if ($detail =~ /Number\s+of\s+topology\s+changes\s+(\d+)/i && $1 > 10) {
        log_output("  WARN: High topology change count ($1) -- possible STP instability\n");
    }

    $ssh->exec('exit');
    $ssh->close();
    log_output("\n");
}

for my $dev (@devices) {
    eval { audit_device($dev) };
    if ($@) {
        log_output("  ERROR: Connection to $dev failed: $@\n\n");
    }
}

close $log_fh if $log_fh;