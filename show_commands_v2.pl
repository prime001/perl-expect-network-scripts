#!/usr/bin/perl
#
# stp_check.pl - Spanning Tree Protocol root bridge and port state audit
#
# Purpose:
#   SSHes into Cisco IOS/IOS-XE switches and audits the STP topology:
#   identifies root bridges per VLAN, reports port state counts, flags
#   topology change events (a leading indicator of network instability),
#   and surfaces any ports stuck in Blocking/Listening state.
#   Designed for rapid triage during outages or scheduled topology reviews.
#
# Usage:
#   ./stp_check.pl -h <host> -u <user> -p <pass> [-e <enable_pass>] [-l <logfile>]
#   ./stp_check.pl -f devices.txt -u <user> -p <pass> [-e <enable_pass>] [-l <logfile>]
#
# Options:
#   -h  Target device IP or hostname
#   -f  File with one device IP/hostname per line (# lines ignored)
#   -u  SSH username
#   -p  SSH password
#   -e  Enable password (omit if not required)
#   -l  Append output to logfile in addition to STDOUT
#
# Prerequisites:
#   cpan Net::SSH::Expect
#
# Tested on: Cisco IOS 15.x, IOS-XE 16.x/17.x
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $pass, $enable, $device_file, $log_file);

GetOptions(
    'host|h=s'   => \$host,
    'user|u=s'   => \$user,
    'pass|p=s'   => \$pass,
    'enable|e=s' => \$enable,
    'file|f=s'   => \$device_file,
    'log|l=s'    => \$log_file,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-e <enable>] [-l <log>]\n";

die "ERROR: Provide -h <host> or -f <file>\n"    unless $host || $device_file;
die "ERROR: Username (-u) is required\n"          unless $user;
die "ERROR: Password (-p) is required\n"          unless $pass;

my @devices;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*[#\s]*$/; push @devices, $_ }
    close $fh;
} else {
    @devices = ($host);
}

my $LOG;
if ($log_file) {
    open $LOG, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub out {
    my $msg = shift;
    print $msg;
    print $LOG $msg if $LOG;
}

sub audit_device {
    my ($target) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    out("=" x 62 . "\n");
    out("Device : $target\nTime   : $ts\n");
    out("=" x 62 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $target,
        user     => $user,
        password => $pass,
        raw_pty  => 1,
        timeout  => 20,
    );

    my $login;
    eval { $login = $ssh->login() };
    if ($@ || !defined $login) {
        out("ERROR: SSH connection failed for $target: " . ($@ || 'no response') . "\n\n");
        return;
    }
    if ($login =~ /(?:assword|denied|incorrect|failed)/i && $login !~ /#|\$/) {
        out("ERROR: Authentication failed for $target\n\n");
        return;
    }

    if ($enable) {
        $ssh->send("enable");
        $ssh->waitfor('Password:', 5) or out("WARN: No enable password prompt on $target\n");
        $ssh->send($enable);
        $ssh->waitfor('#', 5);
    }

    $ssh->exec("terminal length 0");

    my $summary = $ssh->exec("show spanning-tree summary");
    unless (defined $summary && length $summary) {
        out("ERROR: No response from 'show spanning-tree summary' on $target\n\n");
        $ssh->close(); return;
    }

    my $is_root = ($summary =~ /This bridge is the root/i) ? "YES" : "NO";
    my ($mode)  = ($summary =~ /Spanning tree mode\s+(\S+)/i);
    $mode //= 'unknown';

    out(sprintf("STP Mode    : %s\n", $mode));
    out(sprintf("Root Bridge : %s\n", $is_root));

    my %states;
    $states{lc $2} += $1 while $summary =~ /(\d+)\s+(Forwarding|Blocking|Listening|Learning|Disabled)/gi;
    out("Port States :\n");
    out(sprintf("  %-12s %d\n", ucfirst($_), $states{$_})) for sort keys %states;
    out("WARN: Ports in non-forwarding state detected\n") if $states{blocking} || $states{listening};

    my $root_out = $ssh->exec("show spanning-tree root");
    if (defined $root_out && $root_out =~ /VLAN/i) {
        out("\nPer-VLAN Root Bridge:\n");
        out(sprintf("  %-10s %-22s %-8s %s\n", 'VLAN', 'Root MAC', 'Cost', 'Root Port'));
        out("  " . "-" x 55 . "\n");
        while ($root_out =~ /^(VLAN\d+)\s+\d+\s+([\da-f.]+)\s+(\d+).*?(\S+)\s*$/mg) {
            out(sprintf("  %-10s %-22s %-8s %s\n", $1, $2, $3, $4));
        }
    }

    my $tc_out = $ssh->exec("show spanning-tree detail | include topology change|changes occur");
    if (defined $tc_out) {
        my @tc_lines = grep { /topology|occur/i && /\d/ } split /\n/, $tc_out;
        if (@tc_lines) {
            out("\nTopology Change Events (instability indicator):\n");
            for my $line (@tc_lines) {
                $line =~ s/^\s+//;
                out("  $line\n");
            }
        }
    }

    $ssh->exec("exit");
    out("\n");
}

for my $dev (@devices) {
    eval { audit_device($dev) };
    out("ERROR: Exception on $dev: $@\n") if $@;
}

close $LOG if $LOG;