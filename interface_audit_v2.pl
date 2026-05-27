#!/usr/bin/perl
#
# stp_audit.pl - Spanning Tree Protocol Audit Script
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and audits STP topology.
#   Reports root bridge status, topology change counts per VLAN, ports in
#   blocking state, and flags ports stuck in transitional states (Listening/
#   Learning) that may indicate a flapping link or misconfiguration.
#
# Usage:
#   Single device:   ./stp_audit.pl 192.168.1.1
#   Device list:     ./stp_audit.pl -f devices.txt
#   With log file:   ./stp_audit.pl 192.168.1.1 -l /var/log/stp_audit.log
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   Set DEVICE_USER and DEVICE_PASS env vars, or edit defaults below.
#   SSH must be enabled on target devices.
#
# Author: Network Engineering
# Version: 1.0

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my $DEFAULT_USER    = $ENV{DEVICE_USER} // 'admin';
my $DEFAULT_PASS    = $ENV{DEVICE_PASS} // 'cisco';
my $DEFAULT_TIMEOUT = 15;
my $TC_THRESHOLD    = 100;  # topology change count worth flagging

my ($file, $logfile, $help);
GetOptions(
    'f|file=s' => \$file,
    'l|log=s'  => \$logfile,
    'h|help'   => \$help,
) or die "Usage: $0 [-f devices.txt] [-l logfile.log] [host]\n";

if ($help) {
    print "Usage: $0 [options] [host]\n";
    print "  -f FILE   Read device hostnames/IPs from file (one per line)\n";
    print "  -l FILE   Append output to log file\n";
    print "  -h        Show this help\n";
    exit 0;
}

my @devices;
if ($file) {
    open(my $fh, '<', $file) or die "Cannot open device file '$file': $!";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        push @devices, $_ if /\S/;
    }
    close $fh;
} elsif (@ARGV) {
    push @devices, $ARGV[0];
} else {
    die "Usage: $0 [-f devices.txt] [-l logfile.log] [host]\n";
}

die "No devices specified or found in file\n" unless @devices;

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log '$logfile': $!";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my ($host) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);

    out("\n" . "=" x 62 . "\n");
    out("STP Audit | $host | $ts\n");
    out("=" x 62 . "\n");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host       => $host,
            user       => $DEFAULT_USER,
            password   => $DEFAULT_PASS,
            raw_pty    => 1,
            timeout    => $DEFAULT_TIMEOUT,
            ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
        $ssh->run_ssh() or die "SSH process failed to start";
        my $banner = $ssh->login();
        die "Authentication failed or no device prompt" unless $banner && $banner =~ /[>#]/;
    };
    if ($@) {
        out("ERROR connecting to $host: $@\n");
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('#\s*$', 5);

    $ssh->send("show spanning-tree summary\n");
    my $summary = $ssh->waitfor('#\s*$', 15) // '';

    $ssh->send("show spanning-tree detail\n");
    my $detail = $ssh->waitfor('#\s*$', 20) // '';

    $ssh->send("exit\n");
    $ssh->close();

    # Root bridge status
    if ($summary =~ /Root bridge for:\s*(.+)/i) {
        out("ROOT BRIDGE for: $1\n");
    } elsif ($summary =~ /This bridge is the root/i) {
        out("ROOT BRIDGE (all VLANs)\n");
    } else {
        out("Not root bridge on this device\n");
        if ($summary =~ /Root ID\s+Priority\s+(\d+)\s+Address\s+(\S+)/i) {
            out("  Root:  priority=$1  mac=$2\n");
        }
    }

    # Topology change counts per VLAN
    my %tc;
    while ($detail =~ /^VLAN(\d+)\b.*?Number of topology changes\s+(\d+)/gims) {
        $tc{$1} = $2;
    }
    if (%tc) {
        out("\nTopology Change Counts per VLAN:\n");
        for my $vlan (sort { $a <=> $b } keys %tc) {
            my $flag = $tc{$vlan} > $TC_THRESHOLD ? '  *** HIGH - investigate' : '';
            out(sprintf("  VLAN%-5s  TC=%d%s\n", $vlan, $tc{$vlan}, $flag));
        }
    }

    # Ports in blocking state (expected for redundant links, listed for awareness)
    my @blocking;
    while ($detail =~ /^(\S+)\s+of \S+ is Blocking/gim) {
        push @blocking, $1;
    }
    if (@blocking) {
        out("\nBlocking ports (redundant, normal): " . join(', ', @blocking) . "\n");
    }

    # Ports stuck in transitional states (potential issue)
    my @transitional;
    while ($detail =~ /^(\S+)\s+of \S+ is (Listening|Learning)/gim) {
        push @transitional, "$1[$2]";
    }
    if (@transitional) {
        out("\nWARNING - Transitional port states (possible flap or reconfiguration):\n");
        out("  " . join(', ', @transitional) . "\n");
    }

    out("\nAudit complete.\n");
}

for my $host (@devices) {
    audit_device($host);
}

close $log_fh if $log_fh;