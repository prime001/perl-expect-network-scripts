#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# spanning_tree_audit.pl — Cisco IOS Spanning Tree Topology Audit
#
# PURPOSE:
#   Connects to one or more Cisco IOS/IOS-XE switches and audits the
#   Spanning Tree Protocol (STP) topology: root bridge identity, port states,
#   topology change counters, and inconsistent/error-disabled ports.
#   Flags anything that looks wrong so you can catch STP instability before
#   it causes outages.
#
# USAGE:
#   Single device:  ./spanning_tree_audit.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./spanning_tree_audit.pl -f switches.txt -u admin -p secret
#   With log:       ./spanning_tree_audit.pl -h 10.0.0.1 -u admin -p secret -l /tmp/stp.log
#   Custom timeout: ./spanning_tree_audit.pl -h 10.0.0.1 -u admin -p secret -t 45
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   SSH access to target devices with privilege level 1+ (show commands)
#   Devices must be running Cisco IOS or IOS-XE
#
# OUTPUT:
#   Per-device summary: root bridge, port counts by state, TC counter,
#   inconsistent ports. Exit code 1 if any device shows anomalies.
# =============================================================================

my ($host, $user, $pass, $device_file, $log_file, $timeout, $enable_pass);
$timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'f|file=s'    => \$device_file,
    'l|log=s'     => \$log_file,
    't|timeout=i' => \$timeout,
    'e|enable=s'  => \$enable_pass,
) or die "Usage: $0 -h HOST -u USER -p PASS [-f FILE] [-l LOG] [-t TIMEOUT] [-e ENABLE]\n";

die "Provide -h HOST or -f FILE\n" unless $host || $device_file;
die "Username (-u) required\n" unless $user;
die "Password (-p) required\n" unless $pass;

my @devices = $host ? ($host) : do {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    map { chomp; $_ } grep { /\S/ && !/^#/ } <$fh>;
};

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

my $ts    = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $issues = 0;

sub emit {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

emit("=" x 70 . "\n");
emit("STP Audit  $ts\n");
emit("=" x 70 . "\n\n");

for my $dev (@devices) {
    emit("--- $dev ---\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $dev,
            user        => $user,
            password    => $pass,
            raw_pty     => 1,
            timeout     => $timeout,
        );
    };
    if ($@ || !$ssh) {
        emit("  ERROR: Cannot create SSH session: $@\n\n");
        $issues++;
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !$login) {
        emit("  ERROR: Login failed (bad credentials or unreachable)\n\n");
        $issues++;
        next;
    }

    # Enter enable if needed
    if ($enable_pass) {
        $ssh->send("enable");
        $ssh->waitfor('Password:', 10);
        $ssh->send($enable_pass);
        $ssh->waitfor('[$#>]', 10);
    }

    # Disable paging
    $ssh->exec("terminal length 0");

    # Gather STP data
    my $summary = $ssh->exec("show spanning-tree summary") // '';
    my $incon   = $ssh->exec("show spanning-tree inconsistentports") // '';
    my $detail  = $ssh->exec("show spanning-tree detail") // '';

    $ssh->close();

    # Parse: root bridge info
    my %roots;
    while ($summary =~ /^(\S+)\s+\S+\s+\S+\s+Root\s+FWD\s+(\d+)/mg) {
        $roots{$1} = $2;
    }

    # Parse: port state counts from summary totals line
    my ($fwd, $blk, $lis, $lrn, $broken) = (0, 0, 0, 0, 0);
    if ($summary =~ /(\d+)\s+forwarding\s+(\d+)\s+blocking/i) {
        ($fwd, $blk) = ($1, $2);
    }
    $broken++ while $summary =~ /BKN\*/gi;

    # Parse: topology change count (flag if high)
    my $tc_count = 0;
    $tc_count += $1 while $detail =~ /Number of topology changes\s+(\d+)/gi;

    # Parse: inconsistent ports
    my @incon_ports;
    push @incon_ports, "$1 ($2)" while $incon =~ /(\S+)\s+\S+\s+(Root Inconsistent|Loop Inconsistent)/g;

    # Report
    if (%roots) {
        emit("  Root bridges seen:\n");
        emit("    VLAN $_ — root port cost $roots{$_}\n") for sort keys %roots;
    } else {
        emit("  Root bridge: this switch IS root (or no VLANs active)\n");
    }

    emit("  Port states: FWD=$fwd  BLK=$blk  BROKEN=$broken\n");
    emit("  Topology changes (cumulative): $tc_count\n");

    if ($tc_count > 50) {
        emit("  WARN: High TC count ($tc_count) — possible STP instability\n");
        $issues++;
    }
    if ($broken) {
        emit("  WARN: $broken port(s) in BROKEN/BKN state\n");
        $issues++;
    }
    if (@incon_ports) {
        emit("  WARN: Inconsistent ports: " . join(', ', @incon_ports) . "\n");
        $issues++;
    }

    emit("\n");
}

emit("Audit complete. " . ($issues ? "$issues issue(s) flagged." : "No issues found.") . "\n");
close $log_fh if $log_fh;
exit($issues ? 1 : 0);