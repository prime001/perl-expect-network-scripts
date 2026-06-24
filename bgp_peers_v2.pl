#!/usr/bin/perl
# =============================================================================
# bgp_prefix_audit.pl - BGP Prefix Count and Threshold Audit
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers and audits BGP peer prefix counts
#   against configured max-prefix thresholds. Identifies peers approaching
#   or exceeding limits — a critical operational check for ISP handoffs,
#   peering sessions, and leak detection.
#
# Usage:
#   Single device:  ./bgp_prefix_audit.pl -h 10.0.0.1 -u admin -p secret
#   From file:      ./bgp_prefix_audit.pl -f devices.txt -u admin -p secret
#   With log:       ./bgp_prefix_audit.pl -h 10.0.0.1 -u admin -p secret -l /tmp/bgp_audit.log
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to device; 'terminal length 0' supported
#
# Device file format (one IP or hostname per line, # for comments)
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $device_file, $username, $password, $log_file);
my $timeout = 30;
my $warn_pct = 80;

GetOptions(
    'h|host=s'     => \$host_arg,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$log_file,
    't|timeout=i'  => \$timeout,
    'w|warn=i'     => \$warn_pct,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOGFILE] [-t TIMEOUT] [-w WARN_PCT]\n";

die "Must specify -h HOST or -f FILE\n" unless $host_arg || $device_file;
die "Must specify -u username\n" unless $username;
die "Must specify -p password\n" unless $password;

my @devices;
if ($host_arg) {
    push @devices, $host_arg;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*#/ || /^\s*$/; push @devices, $_; }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
out("=" x 70 . "\n");
out("BGP Prefix Audit  |  $ts  |  Warn threshold: ${warn_pct}%\n");
out("=" x 70 . "\n");

for my $host (@devices) {
    out("\n[*] Connecting to $host...\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $username,
        password     => $password,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    eval {
        my $login_out = $ssh->login();
        unless ($login_out =~ /[>#]/) {
            die "Authentication failed or unexpected prompt on $host\n";
        }
    };
    if ($@) {
        out("  [ERROR] $host: $@\n");
        next;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\S+[>#]\s*$', 10);

    $ssh->send("show bgp ipv4 unicast summary");
    my $summary = $ssh->waitfor('\S+[>#]\s*$', $timeout);

    unless ($summary && $summary =~ /BGP router identifier/i) {
        out("  [ERROR] $host: BGP not running or command failed\n");
        $ssh->close();
        next;
    }

    my %peers;
    while ($summary =~ /^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+|NoNeg)/mg) {
        my ($peer_ip, $prefixes) = ($1, $2);
        next if $prefixes eq 'NoNeg';
        $peers{$peer_ip}{received} = $prefixes;
    }

    if (!%peers) {
        out("  [WARN] $host: No established BGP peers found\n");
        $ssh->close();
        next;
    }

    out(sprintf("  %-18s %-10s %-10s %-8s %s\n",
        "Peer", "Received", "MaxPrefix", "Pct", "Status"));
    out("  " . "-" x 60 . "\n");

    for my $peer (sort keys %peers) {
        $ssh->send("show bgp ipv4 unicast neighbors $peer");
        my $detail = $ssh->waitfor('\S+[>#]\s*$', $timeout);

        my $max_prefix = 0;
        if ($detail && $detail =~ /Maximum prefixes:\s*(\d+)/i) {
            $max_prefix = $1;
        }

        my $received = $peers{$peer}{received};
        my $pct = ($max_prefix > 0) ? int(($received / $max_prefix) * 100) : 0;
        my $status = "OK";
        $status = "WARN"     if $max_prefix > 0 && $pct >= $warn_pct;
        $status = "CRITICAL" if $max_prefix > 0 && $pct >= 100;
        $status = "NO-LIMIT" if $max_prefix == 0;

        out(sprintf("  %-18s %-10s %-10s %-8s %s\n",
            $peer, $received,
            ($max_prefix > 0 ? $max_prefix : "none"),
            ($max_prefix > 0 ? "${pct}%" : "n/a"),
            $status));
    }

    $ssh->close();
}

out("\nAudit complete.\n");
close($log_fh) if $log_fh;