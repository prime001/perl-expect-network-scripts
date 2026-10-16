#!/usr/bin/perl
# =============================================================================
# stp_audit.pl - Spanning Tree Protocol Status Auditor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices and audits STP health: identifies
#   root bridges per VLAN, reports port states, flags active topology changes,
#   and highlights any ports stuck in non-forwarding states.
#
# Usage:
#   Single device:  perl stp_audit.pl -h 192.168.1.1 -u admin -p secret
#   Device list:    perl stp_audit.pl -f devices.txt -u admin -p secret
#   With log file:  perl stp_audit.pl -h 10.0.0.1 -u admin -p secret -l stp.log
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#
# devices.txt format: one IP or hostname per line, blank lines/comments ignored
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $pass, $file, $logfile, $timeout);
$timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'f|file=s'     => \$file,
    'l|log=s'      => \$logfile,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h HOST -u USER -p PASS [-f FILE] [-l LOGFILE] [-t TIMEOUT]\n";

die "Credentials required: -u USER -p PASS\n" unless $user && $pass;
die "Specify -h HOST or -f FILE\n"             unless $host || $file;

my @devices = $host ? ($host) : ();
if ($file) {
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    while (<$fh>) {
        chomp;
        s/#.*//;
        s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open logfile $logfile: $!\n";
}

sub out {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my $dev = shift;
    my $ts  = strftime('%Y-%m-%d %H:%M:%S', localtime);

    out("\n=== STP Audit: $dev [$ts] ===\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $dev,
        user     => $user,
        password => $pass,
        timeout  => $timeout,
        raw_pty  => 1,
    );

    eval {
        my $login = $ssh->login();
        die "Login failed\n" unless $login && $login !~ /[Pp]ermission|[Dd]enied/;
    };
    if ($@) {
        out("  [ERROR] Cannot connect to $dev: $@");
        return;
    }

    $ssh->exec("terminal length 0");

    my $summary = $ssh->exec("show spanning-tree summary");
    if (!$summary || $summary =~ /Invalid|Error/) {
        out("  [ERROR] Failed to retrieve STP data from $dev\n");
        $ssh->close();
        return;
    }

    my ($root_count, $vlan_count, $tcn_count) = (0, 0, 0);
    my @alerts;

    for my $line (split /\n/, $summary) {
        $vlan_count++      if $line =~ /^VLAN\d+\s+/i;
        $root_count++      if $line =~ /\broot\b/i && $line =~ /^VLAN/i;
        if ($line =~ /topology\s+change/i) {
            if ($line =~ /(\d+)\s+topology\s+change/i && $1 > 0) {
                push @alerts, "  [WARN] $1 topology change(s) detected";
                $tcn_count += $1;
            }
        }
    }

    out("  VLANs tracked by STP : $vlan_count\n");
    out("  VLANs where root     : $root_count\n");

    my $detail = $ssh->exec("show spanning-tree detail | include ieee|from|topology|port");

    my %ports_blocking;
    my %ports_listening;
    for my $line (split /\n/, $detail) {
        if ($line =~ /(\S+)\s+of\s+\S+\s+is\s+(BLK|blocking|LIS|listening)/i) {
            my ($port, $state) = ($1, lc $2);
            if ($state =~ /blk|block/) {
                $ports_blocking{$port}++;
            } elsif ($state =~ /lis/) {
                push @alerts, "  [WARN] Port $port stuck in LISTENING state";
                $ports_listening{$port}++;
            }
        }
        if ($line =~ /Number of topology changes (\d+)/i && $1 > 0) {
            push @alerts, "  [WARN] Root-level TCN count: $1";
        }
    }

    my $blocking = scalar keys %ports_blocking;
    out("  Ports in BLK state   : $blocking" . ($blocking ? " (" . join(', ', sort keys %ports_blocking) . ")" : "") . "\n");

    if (@alerts) {
        out("  --- Alerts ---\n");
        out("$_\n") for @alerts;
    } else {
        out("  [OK] No STP anomalies detected\n");
    }

    $ssh->close();
}

audit_device($_) for @devices;

close $log_fh if $log_fh;
out("\nAudit complete. " . scalar(@devices) . " device(s) checked.\n");