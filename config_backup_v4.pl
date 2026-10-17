#!/usr/bin/perl
#
# spanning_tree_check.pl - Spanning Tree Protocol Audit Tool
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches via SSH and audits spanning tree
#   health across all active VLANs. Reports STP mode, root bridge ownership,
#   port state counts, and flags topology change activity that signals
#   instability requiring investigation.
#
# Usage:
#   Single device:
#     ./spanning_tree_check.pl --host 10.0.1.1 --user admin --pass s3cr3t
#   Multiple devices with log:
#     ./spanning_tree_check.pl --file switches.txt --user admin --pass s3cr3t --log stp_audit.log
#
# Device file format: one IP or hostname per line; blank lines and # comments ignored
#
# Prerequisites:
#   cpan install Net::SSH::Expect

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($opt_host, $opt_user, $opt_pass, $opt_log, $opt_file);
my $opt_timeout = 30;

GetOptions(
    'host=s'    => \$opt_host,
    'user=s'    => \$opt_user,
    'pass=s'    => \$opt_pass,
    'log=s'     => \$opt_log,
    'file=s'    => \$opt_file,
    'timeout=i' => \$opt_timeout,
) or die "Usage: $0 --host <ip>|--file <list> --user <user> --pass <pass> [--log <file>] [--timeout <sec>]\n";

die "Must specify --host or --file\n" unless $opt_host || $opt_file;
die "Must specify --user\n"           unless $opt_user;
die "Must specify --pass\n"           unless $opt_pass;

my @hosts;
if ($opt_file) {
    open(my $fh, '<', $opt_file) or die "Cannot open device file '$opt_file': $!\n";
    while (<$fh>) { chomp; next if /^\s*$/ || /^\s*#/; push @hosts, $_; }
    close $fh;
} else {
    push @hosts, $opt_host;
}

my $log_fh;
if ($opt_log) {
    open($log_fh, '>', $opt_log) or die "Cannot open log file '$opt_log': $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
out("=" x 62 . "\n");
out("Spanning Tree Audit  --  $ts\n");
out("=" x 62 . "\n\n");

my ($ok, $failed) = (0, 0);

for my $host (@hosts) {
    out("Host: $host\n");
    out("-" x 40 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        user       => $opt_user,
        password   => $opt_pass,
        raw_pty    => 1,
        timeout    => $opt_timeout,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    eval { $ssh->login() };
    if ($@) {
        out("  FAIL: SSH error - " . ($@ =~ s/\n/ /gr) . "\n\n");
        $failed++;
        next;
    }

    $ssh->exec("terminal length 0");

    my $summary = $ssh->exec("show spanning-tree summary");
    if (!$summary || $summary =~ /Invalid input|% Error/i) {
        out("  FAIL: Command not supported (non-IOS device or insufficient privilege)\n\n");
        $ssh->close();
        $failed++;
        next;
    }

    # STP operating mode
    my $mode = ($summary =~ /protocol\s+(\S+)/i) ? uc($1) : "unknown";

    # VLANs for which this switch is root
    my @root_vlans;
    if ($summary =~ /Root bridge for:\s+(.+)/i) {
        my $vlan_str = $1;
        $vlan_str =~ s/\s+$//;
        @root_vlans = split(/,\s*/, $vlan_str);
    }

    # Port state totals from the summary footer line: "N vlans  BLK  LST  LRN  FWD  ACTIVE"
    my ($blk, $lst, $lrn, $fwd) = (0, 0, 0, 0);
    if ($summary =~ /\d+\s+vlan[s]?\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/i) {
        ($blk, $lst, $lrn, $fwd) = ($1, $2, $3, $4);
    }

    # Topology change count via detail grep
    my $tc_total = 0;
    my $detail = $ssh->exec("show spanning-tree detail | include topology change");
    $tc_total += $1 while ($detail =~ /(\d+)\s+topology changes/gi);

    out(sprintf("  STP Mode:     %s\n", $mode));
    out(sprintf("  Root Bridge:  %s\n",
        @root_vlans ? join(", ", @root_vlans) : "no VLANs (downstream switch)"));
    out(sprintf("  Port States:  Forwarding=%-4d Blocking=%-4d Learning=%-4d Listening=%d\n",
        $fwd, $blk, $lrn, $lst));

    if ($tc_total > 0) {
        out("  WARNING:      $tc_total topology change(s) logged -- identify TCN source\n");
    }
    if ($lst > 0 || $lrn > 0) {
        out("  WARNING:      Ports in transitional states -- topology may still be converging\n");
    }
    if ($blk > 0) {
        out("  INFO:         $blk blocked port(s) -- normal redundancy behavior\n");
    }

    out("\n");
    $ssh->close();
    $ok++;
}

close $log_fh if $log_fh;
out(sprintf("Audit complete: %d succeeded, %d failed, %d total\n", $ok, $failed, scalar @hosts));
out("Log written to: $opt_log\n") if $opt_log;