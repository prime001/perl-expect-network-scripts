#!/usr/bin/perl
# =============================================================================
# stp_audit.pl - Spanning Tree Protocol health audit for Cisco IOS/IOS-XE
#
# PURPOSE:
#   Audits STP health across one or more switches: identifies root bridge
#   placement, counts topology changes, flags instability, and detects
#   BPDU guard err-disabled ports. Essential for validating STP design
#   and hunting the source of network flaps.
#
# USAGE:
#   Single device:  perl stp_audit.pl -h 192.168.1.1 -u admin -p secret
#   From file:      perl stp_audit.pl -f switches.txt -u admin -p secret
#   With log:       perl stp_audit.pl -h 10.0.0.1 -u admin -p secret -l stp.log
#   Custom timeout: perl stp_audit.pl -h 10.0.0.1 -u admin -p secret -t 20
#
# PREREQUISITES:
#   cpan install Net::SSH::Expect Getopt::Long
#
# DEVICE FILE FORMAT (one IP or hostname per line, # for comments):
#   10.0.0.1
#   10.0.0.2
#   # sw-distribution-01
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $logfile, $timeout);
$timeout = 15;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$file,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'l|log=s'     => \$logfile,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOGFILE] [-t TIMEOUT]\n";

die "Provide -h HOST or -f FILE\n" unless $host || $file;
die "Provide -u USER and -p PASS\n" unless $user && $pass;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $file) or die "Cannot open device file '$file': $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        push @devices, $_ if length $_;
    }
    close $fh;
}

my $LOG;
if ($logfile) {
    open($LOG, '>>', $logfile) or die "Cannot open log '$logfile': $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=" x 68);
output("STP Audit Report - $ts");
output("=" x 68);

for my $dev (@devices) {
    output("\n--- Device: $dev ---");
    eval { audit_stp($dev) };
    if ($@) {
        (my $err = $@) =~ s/ at .+ line \d+.*//s;
        output("  ERROR: $err");
    }
}

close $LOG if $LOG;

sub audit_stp {
    my ($device) = @_;

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    my $login = eval { $ssh->login() };
    die "SSH connection failed: " . ($@ || 'timeout') if $@ || !defined $login;
    die "Authentication failed (bad credentials)" if $login =~ /denied|invalid|fail/i;

    $ssh->exec('terminal length 0');

    my $summary = $ssh->exec('show spanning-tree summary');
    my $detail  = $ssh->exec('show spanning-tree detail');

    $ssh->exec('exit');

    parse_and_report($device, $summary, $detail);
}

sub parse_and_report {
    my ($device, $summary, $detail) = @_;
    my $issues = 0;

    # Root bridge status
    if ($summary =~ /Root bridge for:\s*(.+)/i) {
        (my $vlans = $1) =~ s/\s+$//;
        output("  Root bridge for: $vlans");
    } else {
        output("  Root bridge: not root for any VLAN on this switch");
    }

    # Mode (PVST, Rapid-PVST, MST)
    if ($summary =~ /Switch is in (\S+) mode/i) {
        output("  STP mode: $1");
    }

    # Port state counts from summary
    my %states;
    while ($summary =~ /(\d+)\s+(Blocking|Listening|Learning|Forwarding|Loopback)/gi) {
        $states{ucfirst(lc($2))} += $1;
    }
    for my $state (qw(Forwarding Learning Listening Blocking Loopback)) {
        next unless exists $states{$state};
        output(sprintf("  %-14s %d port(s)", "$state:", $states{$state}));
    }
    if (($states{Blocking} || 0) > 25) {
        output("  WARN: Unusually high blocking port count -- verify topology design");
        $issues++;
    }

    # Topology change totals from detail output
    my $tc_total = 0;
    $tc_total += $1 while $detail =~ /Number of topology changes (\d+)/gi;
    output("  Topology changes (cumulative): $tc_total");
    if ($tc_total > 150) {
        output("  WARN: High TC count ($tc_total) indicates ongoing or recent instability");
        $issues++;
    }

    # Last topology change timestamp
    if ($detail =~ /last change occurred\s+([\d:]+\s+(?:ago)?)/i) {
        output("  Last topology change: $1");
    }

    # Detect BPDU guard err-disabled ports
    my @errdis;
    push @errdis, $1 while $detail =~ /^(\S+(?:\/\d+)+)\s+.*\berr.disabled\b/gim;
    if (@errdis) {
        output("  WARN: BPDU guard err-disabled ports (" . scalar(@errdis) . "): " . join(', ', @errdis));
        $issues++;
    }

    # Ports stuck in Listening/Learning longer than expected
    my @stuck;
    while ($detail =~ /(\S+(?:\/\d+)+).*?has been (?:listening|learning) for (\d+) second/gis) {
        push @stuck, "$1 ($2s)" if $2 > 60;
    }
    if (@stuck) {
        output("  WARN: Ports stuck in transient STP state: " . join(', ', @stuck));
        $issues++;
    }

    output($issues == 0 ? "  STATUS: OK" : "  STATUS: $issues issue(s) found -- review above warnings");
}

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $LOG "$msg\n" if $LOG;
}