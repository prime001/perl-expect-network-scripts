#!/usr/bin/perl
#
# stp_audit.pl - Spanning Tree Protocol Audit Tool
#
# Purpose:
#   Audits STP/RSTP/MSTP state on Cisco IOS/IOS-XE switches. Reports root
#   bridge placement per VLAN, ports in non-forwarding states, topology change
#   counts, and BPDU guard err-disabled ports. Use after topology changes or
#   as a scheduled health check to confirm STP convergence matches design.
#
# Usage:
#   stp_audit.pl -h <host> -u <user> [-p <pass>] [-l <logfile>]
#   stp_audit.pl -f <device_list> -u <user> [-p <pass>] [-l <logfile>]
#
#   If -p is omitted, reads NET_PASS env var or prompts securely.
#   Device list file: one IP/hostname per line, # for comments.
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#
# Example:
#   stp_audit.pl -h 10.0.1.1 -u admin -l /tmp/stp_$(date +%F).log

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($host, $user, $pass, $file, $logfile);
my $timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'f|file=s'    => \$file,
    'l|log=s'     => \$logfile,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h <host>|-f <file> -u <user> [-p <pass>] [-l <log>]\n";

die "Specify -h <host> or -f <device_list>\n" unless $host || $file;
die "Username required: -u <user>\n" unless $user;

unless ($pass) {
    $pass = $ENV{NET_PASS};
    unless ($pass) {
        print "Password for $user: ";
        system("stty -echo");
        chomp($pass = <STDIN>);
        system("stty echo");
        print "\n";
    }
}

my @devices;
if ($file) {
    open(my $fh, '<', $file) or die "Cannot open device list '$file': $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>', $logfile) or die "Cannot open log '$logfile': $!\n";
    $log_fh->autoflush(1);
}

sub out {
    print @_;
    print $log_fh @_ if $log_fh;
}

sub audit_device {
    my ($device) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    out("\n" . "=" x 60 . "\n");
    out("STP Audit: $device  [$ts]\n");
    out("=" x 60 . "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host       => $device,
            user       => $user,
            password   => $pass,
            raw_pty    => 1,
            timeout    => $timeout,
            ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=15 -o BatchMode=no',
        );
    };
    if ($@ || !$ssh) {
        out("  ERROR: Failed to initialize SSH for $device: $@\n");
        return;
    }

    my $login_out = eval { $ssh->login() };
    if ($@ || ($login_out && $login_out =~ /Permission denied|auth.*fail/i)) {
        out("  ERROR: Authentication failed for $device\n");
        return;
    }

    $ssh->exec("terminal length 0");
    $ssh->exec("terminal width 200");

    my $summary   = $ssh->exec("show spanning-tree summary") // "";
    my ($mode)    = $summary =~ /Switch is in (\S+) mode/i;
    my $is_root   = $summary =~ /This bridge is the root/i ? "YES" : "NO";
    my ($tc_count)= $summary =~ /(\d+)\s+topology change/i;
    my ($bpdu_err)= $summary =~ /(\d+)\s+(?:ports? )?in err-disabled/i;

    out("  STP Mode        : " . ($mode    // "unknown") . "\n");
    out("  This Is Root    : $is_root\n");
    out("  Topology Changes: " . ($tc_count // "N/A") . "\n");
    out("  BPDU Err-Disable: " . ($bpdu_err // "0")   . " port(s)\n");

    my $detail = $ssh->exec("show spanning-tree detail") // "";
    my @blocked;
    while ($detail =~ /^(\S+)\s+of \S+ is (blocking|discarding)/gim) {
        push @blocked, "$1 ($2)";
    }
    if (@blocked) {
        out("  Non-Forwarding Ports:\n");
        out("    $_\n") for @blocked;
    } else {
        out("  Non-Forwarding Ports: none\n");
    }

    my $bridge = $ssh->exec("show spanning-tree bridge") // "";
    my @vlan_lines;
    for my $line (split /\n/, $bridge) {
        if ($line =~ /^(VLAN\d+|\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+\.\d+)/i) {
            push @vlan_lines, sprintf("    %-12s  Bridge: %-20s  Prio: %d  Hello: %ss\n",
                $1, $2, $3, $5);
            last if @vlan_lines >= 8;
        }
    }
    if (@vlan_lines) {
        out("  Per-VLAN Root Info (up to 8):\n");
        out($_) for @vlan_lines;
    }

    $ssh->close();
    out("  Audit complete.\n");
}

out("STP Audit Run  -- " . strftime("%Y-%m-%d %H:%M:%S", localtime) . "\n");
out("Targets: " . scalar(@devices) . " device(s)\n");

audit_device($_) for @devices;

out("\n--- Audit finished ---\n");

if ($log_fh) {
    close($log_fh);
    print "Log written to: $logfile\n";
}