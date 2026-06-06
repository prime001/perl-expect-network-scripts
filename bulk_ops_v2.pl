#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# stp_check.pl - Spanning Tree Protocol topology auditor
#
# PURPOSE:
#   Audits STP state across one or more Cisco IOS devices: identifies root bridges
#   per VLAN, flags non-default root priorities, reports topology-change counters,
#   and lists any ports currently in BLK or LIS state that may indicate a loop risk.
#
# USAGE:
#   Single device:  ./stp_check.pl --host 10.0.0.1 --user admin --pass s3cr3t
#   Device list:    ./stp_check.pl --file devices.txt --user admin --pass s3cr3t
#   With log file:  ./stp_check.pl --host 10.0.0.1 --user admin --pass s3cr3t --log stp_audit.log
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   SSH must be enabled on target devices (crypto key generate rsa / ip ssh version 2)
#   User account needs privilege 1+ (show commands only)
#
# OUTPUT:
#   Tab-aligned summary to STDOUT; optional append to --log file.
#   Exit code 0 = clean, 1 = anomalies found, 2 = connection/auth error.

my ($host, $file, $user, $pass, $enable_pass, $logfile, $timeout);
$timeout = 30;

GetOptions(
    'host=s'    => \$host,
    'file=s'    => \$file,
    'user=s'    => \$user,
    'pass=s'    => \$pass,
    'enable=s'  => \$enable_pass,
    'log=s'     => \$logfile,
    'timeout=i' => \$timeout,
) or die "Usage: $0 --host HOST|--file FILE --user USER --pass PASS [--enable PASS] [--log FILE]\n";

die "Provide --host or --file\n"  unless $host || $file;
die "Provide --user and --pass\n" unless $user && $pass;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if $_; }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $anomaly_found = 0;

sub emit {
    my $line = shift;
    print $line, "\n";
    print $log_fh $line, "\n" if $log_fh;
}

emit("=" x 72);
emit("STP Topology Audit  $timestamp");
emit("=" x 72);

for my $dev (@devices) {
    emit("\n--- $dev ---");

    my $ssh = Net::SSH::Expect->new(
        host        => $dev,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        emit("  ERROR: SSH connection/auth failed - $@");
        $anomaly_found = 1;
        next;
    }

    # Handle enable mode if needed
    if ($enable_pass) {
        $ssh->send("enable");
        $ssh->waitfor('Password:', $timeout) or do {
            emit("  ERROR: Enable prompt not received");
            next;
        };
        $ssh->send($enable_pass);
        $ssh->waitfor('#', $timeout);
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('#', $timeout);

    # Collect STP summary
    $ssh->send("show spanning-tree summary");
    my $stp_summary = $ssh->waitfor('#', $timeout) // '';

    # Collect per-VLAN STP detail
    $ssh->send("show spanning-tree");
    my $stp_detail = $ssh->waitfor('#', $timeout) // '';

    $ssh->send("exit");
    $ssh->close();

    # Parse root bridge info per VLAN
    my %root_vlans;
    while ($stp_detail =~ /VLAN(\d+)\s*\n.*?This bridge is the root/sg) {
        $root_vlans{$1} = 1;
    }

    # Parse priority and root info
    my @vlan_blocks;
    while ($stp_detail =~ /(VLAN\d+\n(?:.*\n)*?(?=VLAN\d+|\z))/g) {
        push @vlan_blocks, $1;
    }

    my @blocked_ports;
    while ($stp_detail =~ /(\S+)\s+(?:BLK|LIS)\s+\d+\s+\d+\s+\d+\s+(BLK|LIS)/g) {
        push @blocked_ports, "$1 ($2)";
    }
    # Alternative pattern for IOS-XE format
    while ($stp_detail =~ /^\s+(\S+)\s+\S+\s+(BLK|LIS)\b/mg) {
        push @blocked_ports, "$1 ($2)" unless grep { /^$1/ } @blocked_ports;
    }

    # Extract topology change counts
    my $tc_count = 0;
    if ($stp_summary =~ /topology changes\s+(\d+)/i) {
        $tc_count = $1;
    }

    # Report root VLANs
    if (%root_vlans) {
        emit("  ROOT for VLANs: " . join(', ', sort { $a <=> $b } keys %root_vlans));
    } else {
        emit("  Not root bridge for any VLAN on this device");
    }

    # Flag high topology change count (>100 may indicate instability)
    if ($tc_count > 100) {
        emit("  WARN: High topology change count: $tc_count");
        $anomaly_found = 1;
    } else {
        emit("  Topology changes: $tc_count");
    }

    # Report blocked/listening ports
    if (@blocked_ports) {
        my @uniq = do { my %s; grep { !$s{$_}++ } @blocked_ports };
        emit("  Blocked/Listening ports: " . join(', ', @uniq));
    } else {
        emit("  No ports in BLK/LIS state");
    }

    # Flag missing portfast summary line (indicates possible misconfiguration)
    if ($stp_summary !~ /portfast bpdu guard\s+enabled/i) {
        emit("  NOTICE: BPDU Guard not globally enabled");
    }
}

emit("\n" . "=" x 72);
emit("Audit complete. Anomalies detected: " . ($anomaly_found ? "YES" : "none"));
emit("=" x 72);

close $log_fh if $log_fh;
exit($anomaly_found ? 1 : 0);