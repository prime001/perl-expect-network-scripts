#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# spanning_tree_audit.pl - Spanning Tree Protocol Status Auditor
#
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE switches via SSH and collects
#   spanning tree status across all VLANs. Reports root bridge ownership,
#   port states (FWD/BLK/LIS/LRN), and flags any topology-change indicators
#   that may signal instability or misconfiguration.
#
# Usage:
#   ./spanning_tree_audit.pl -h 192.168.1.1 -u admin -p secret
#   ./spanning_tree_audit.pl -f device_list.txt -u admin -p secret -l stp_audit.log
#   ./spanning_tree_audit.pl -h 10.0.0.1 -u admin -p secret --pvst
#
# Prerequisites:
#   - Perl modules: Net::SSH::Expect, Getopt::Long
#     Install: cpanm Net::SSH::Expect
#   - SSH access enabled on target devices
#   - User account with at least privilege 1 (show commands only)
#
# Output:
#   Prints per-VLAN STP summary to STDOUT and optional log file.
#   Highlights BLK ports, root elections, and TC (topology change) counts.
#
# Author:  Network Engineering Team
# Version: 1.0
# =============================================================================

my ($host, $user, $pass, $device_file, $log_file, $pvst_mode, $timeout);
my @hosts;

GetOptions(
    'h|host=s'    => \$host,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'f|file=s'    => \$device_file,
    'l|log=s'     => \$log_file,
    'pvst'        => \$pvst_mode,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l logfile] [--pvst] [-t timeout]\n";

$timeout //= 30;
die "Must provide -u username\n" unless $user;
die "Must provide -p password\n" unless $pass;

if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open device file '$device_file': $!\n";
    while (<$fh>) {
        chomp;
        s/#.*//;
        s/^\s+|\s+$//g;
        push @hosts, $_ if $_;
    }
    close $fh;
} elsif ($host) {
    push @hosts, $host;
} else {
    die "Must provide -h <host> or -f <file>\n";
}

my $LOG;
if ($log_file) {
    open($LOG, '>>', $log_file) or die "Cannot open log file '$log_file': $!\n";
}

sub log_print {
    my ($msg) = @_;
    print $msg;
    print $LOG $msg if $LOG;
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
log_print("=" x 70 . "\n");
log_print("Spanning Tree Audit  --  $timestamp\n");
log_print("=" x 70 . "\n\n");

for my $device (@hosts) {
    log_print("Device: $device\n");
    log_print("-" x 50 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_output = eval { $ssh->login() };
    if ($@ || !defined $login_output) {
        log_print("  ERROR: Cannot connect to $device -- $@\n\n");
        next;
    }

    if ($login_output =~ /[Pp]assword|[Aa]uth|[Dd]enied/) {
        log_print("  ERROR: Authentication failed on $device\n\n");
        next;
    }

    # Disable paging to avoid --More-- prompts
    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#', $timeout) or do {
        log_print("  ERROR: Prompt not detected on $device\n\n");
        next;
    };

    # Collect hostname for display
    my $prompt = $ssh->get_before();
    (my $hostname = $prompt) =~ s/.*\n(\S+)[#>]\s*$/$1/s;
    $hostname = $device unless $hostname;

    # Run STP summary command
    my $stp_cmd = $pvst_mode ? "show spanning-tree summary" : "show spanning-tree detail";
    $ssh->send($stp_cmd);
    my $stp_out = $ssh->waitfor('\$|#', $timeout * 2);

    unless (defined $stp_out && $stp_out =~ /VLAN|vlan|Spanning/i) {
        log_print("  WARNING: No spanning tree output from $device (STP disabled or unsupported)\n\n");
        $ssh->close();
        next;
    }

    # Parse and report key STP data
    my $root_count    = () = $stp_out =~ /This bridge is the root/gi;
    my $tc_count      = 0;
    my $blocking_ports = 0;

    while ($stp_out =~ /Number of topology changes (\d+)/gi) {
        $tc_count += $1;
    }
    $blocking_ports = () = $stp_out =~ /\bBLK\b|\bBLOCKING\b/gi;

    # Extract per-VLAN root bridge info
    my %vlan_root;
    while ($stp_out =~ /VLAN(\d+)\s+.*?Root ID.*?Address\s+([0-9a-fA-F.]+)/gsi) {
        $vlan_root{$1} = $2;
    }
    # Simpler pattern for summary mode
    while ($stp_out =~ /^(\w+VLAN\S+)\s+(\w+)\s+(\d+)\s+(\d+)\s+(\d+)/gm) {
        # PVST summary: VLAN  Mode  BLK  LIS  LRN  FWD  STP Active
    }

    log_print("  Host            : $hostname\n");
    log_print("  VLANs as Root   : $root_count\n");
    log_print("  Blocking Ports  : $blocking_ports\n");
    log_print("  Total Topo Changes: $tc_count\n");

    if ($tc_count > 50) {
        log_print("  *** ALERT: High topology change count ($tc_count) -- check for flapping ports\n");
    }
    if ($blocking_ports == 0 && $root_count == 0) {
        log_print("  *** WARNING: No blocking ports detected and not root -- possible STP disabled or single uplink\n");
    }

    # Per-VLAN root addresses if found
    if (%vlan_root) {
        log_print("  Root Bridges by VLAN:\n");
        for my $vlan (sort { $a <=> $b } keys %vlan_root) {
            log_print(sprintf("    VLAN %4d  Root MAC: %s\n", $vlan, $vlan_root{$vlan}));
        }
    }

    $ssh->send("exit");
    $ssh->close();
    log_print("\n");
}

log_print("Audit complete.\n");
close($LOG) if $LOG;