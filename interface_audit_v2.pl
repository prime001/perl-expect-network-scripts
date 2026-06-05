```perl
#!/usr/bin/perl
#
# stp_audit.pl - Spanning Tree Protocol Topology Auditor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches via SSH and audits STP state:
#   root bridge placement, port roles, topology change counts, and any
#   ports in blocking or inconsistent states. Useful for validating STP
#   topology after network changes or troubleshooting outage root causes.
#
# Usage:
#   ./stp_audit.pl <device_ip> [username] [password]
#   ./stp_audit.pl --file devices.txt [username] [password]
#   NET_USER=admin NET_PASS=secret ./stp_audit.pl 10.0.0.1
#
# Output:
#   Results to STDOUT and stp_audit_YYYYMMDD_HHMMSS.log
#
# Prerequisites:
#   cpan install Expect
#   SSH access to target device(s), read-only privilege sufficient
#
# Tested on: Cisco IOS 15.x, IOS-XE 16.x/17.x

use strict;
use warnings;
use Expect;
use POSIX qw(strftime);
use Getopt::Long;

my $timeout    = 30;
my $timestamp  = strftime('%Y%m%d_%H%M%S', localtime);
my $log_file   = "stp_audit_${timestamp}.log";
my $device_file;

Getopt::Long::Configure('pass_through');
GetOptions('file=s' => \$device_file);

my @devices;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    @devices = grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
    close $fh;
} elsif (@ARGV >= 1) {
    push @devices, shift @ARGV;
} else {
    die "Usage: $0 <device_ip> [user] [pass]\n       $0 --file devices.txt [user] [pass]\n";
}

my $username = shift @ARGV // $ENV{NET_USER} // 'admin';
my $password = shift @ARGV // $ENV{NET_PASS} // do {
    local $| = 1;
    print "Password: ";
    system('stty', '-echo');
    chomp(my $p = <STDIN>);
    system('stty', 'echo');
    print "\n";
    $p;
};

open my $log_fh, '>', $log_file or die "Cannot open $log_file: $!\n";

sub out {
    my $msg = shift;
    print $msg;
    print $log_fh $msg;
}

sub audit_device {
    my $host = shift;
    out("\n" . ('=' x 62) . "\n");
    out("Device: $host  [" . strftime('%Y-%m-%d %H:%M:%S', localtime) . "]\n");
    out('=' x 62 . "\n");

    my $exp = Expect->new;
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${username}\@${host}")) {
        out("ERROR: Failed to spawn SSH for $host\n");
        return;
    }

    my $logged_in = 0;
    $exp->expect($timeout,
        [ qr/[Pp]assword:/,  sub { $exp->send("$password\n"); exp_continue; } ],
        [ qr/yes\/no/i,      sub { $exp->send("yes\n");        exp_continue; } ],
        [ qr/[>#]/,          sub { $logged_in = 1; }                           ],
        [ 'timeout',         sub { out("ERROR: Login timeout on $host\n"); }   ],
    );

    unless ($logged_in) {
        $exp->soft_close;
        return;
    }

    $exp->send("terminal length 0\n");
    $exp->expect($timeout, qr/[>#]/);

    out("\n[STP Summary]\n");
    $exp->send("show spanning-tree summary\n");
    $exp->expect($timeout, [ qr/[>#]/ => sub {
        for my $line (split /\n/, $exp->before) {
            next unless $line =~ /\S/;
            next if $line =~ /^show spanning/;
            out("  $line\n");
        }
    }]);

    out("\n[Root Bridge & Topology Changes per VLAN]\n");
    $exp->send("show spanning-tree detail | include VLAN|is root|change count|from last change\n");
    $exp->expect($timeout, [ qr/[>#]/ => sub {
        my $vlan = 'VLAN?';
        for my $line (split /\n/, $exp->before) {
            next unless $line =~ /\S/;
            $vlan = $1 if $line =~ /(VLAN\d+)/i;
            if ($line =~ /This bridge is the root/i) {
                out("  [$vlan] ROOT BRIDGE on this device\n");
            }
            if ($line =~ /Topology change count:\s*(\d+)/i) {
                my $count = $1;
                my $flag = $count > 0 ? ' *** WARNING ***' : '';
                out("  [$vlan] Topology changes: $count$flag\n");
            }
            if ($line =~ /from last change occurred/i) {
                out("  [$vlan] $line\n");
            }
        }
    }]);

    out("\n[Blocked / Non-Forwarding Ports]\n");
    $exp->send("show spanning-tree blockedports\n");
    $exp->expect($timeout, [ qr/[>#]/ => sub {
        my @blocked = grep { /\S/ && !/^show spanning|blocked/i } split /\n/, $exp->before;
        if (@blocked) {
            out("  $_\n") for @blocked;
        } else {
            out("  None - all ports forwarding\n");
        }
    }]);

    out("\n[PortFast / BPDU Guard Enabled Ports]\n");
    $exp->send("show spanning-tree interface detail | include Port|PortFast|Bpdu\n");
    $exp->expect($timeout, [ qr/[>#]/ => sub {
        my $iface = '';
        for my $line (split /\n/, $exp->before) {
            next unless $line =~ /\S/;
            next if $line =~ /^show spanning/;
            $iface = $1 if $line =~ /^Port\s+\d+\s+\((\S+)\)/;
            if ($line =~ /Portfast\s+is\s+enabled|Bpdu\s+guard\s+is\s+enabled/i) {
                out("  $iface: $line\n");
            }
        }
    }]);

    $exp->send("exit\n");
    $exp->soft_close;
    out("\nCompleted: $host\n");
}

out("STP Audit  |  Started: " . strftime('%Y-%m-%d %H:%M:%S', localtime) . "\n");
out("Log: $log_file\n");

audit_device($_) for @devices;

out("\nDone. " . scalar(@devices) . " device(s) audited.\n");
close $log_fh;
```