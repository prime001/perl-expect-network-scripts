#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# stp_audit.pl - Spanning Tree Protocol topology auditor
#
# PURPOSE:
#   Connects to one or more Cisco IOS/IOS-XE devices and audits the STP
#   topology: root bridge identity, port roles/states, TC counters, and
#   any ports in BLOCKING or LISTENING state that may indicate instability.
#
# USAGE:
#   Single device:  perl stp_audit.pl -H 192.168.1.1 -u admin -p secret
#   Device file:    perl stp_audit.pl -f devices.txt -u admin -p secret -l stp_report.log
#   With VLAN:      perl stp_audit.pl -H 10.0.0.1 -u admin -p secret -v 100
#
# PREREQUISITES:
#   cpanm Net::SSH::Expect
#   SSH must be enabled on target device; enable password optional (-e flag)
#   Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x

my ($host, $file, $user, $pass, $enable, $logfile, $vlan, $timeout);
$timeout = 15;

GetOptions(
    'H|host=s'    => \$host,
    'f|file=s'    => \$file,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'e|enable=s'  => \$enable,
    'l|log=s'     => \$logfile,
    'v|vlan=s'    => \$vlan,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -H host | -f file -u user -p pass [-e enable] [-l logfile] [-v vlan]\n";

die "Specify -H <host> or -f <file>\n" unless $host || $file;
die "Specify -u <user> and -p <pass>\n" unless $user && $pass;

my @devices = $host ? ($host) : do {
    open my $fh, '<', $file or die "Cannot open $file: $!";
    grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
};

my $log_fh;
if ($logfile) {
    open $log_fh, '>', $logfile or die "Cannot open log $logfile: $!";
}

sub output {
    print @_;
    print $log_fh @_ if $log_fh;
}

sub audit_device {
    my ($device) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    output("\n" . "=" x 60 . "\n");
    output("Host: $device  Time: $ts\n");
    output("=" x 60 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_out = eval { $ssh->login() };
    if ($@ || !defined $login_out) {
        output("ERROR: SSH login failed to $device: $@\n");
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('.*[>#]\s*$', 5);

    if ($enable) {
        $ssh->send("enable\n");
        my $result = $ssh->waitfor('Password:|[>#]\s*$', 5);
        if ($result && $result =~ /Password:/) {
            $ssh->send("$enable\n");
            $ssh->waitfor('.*#\s*$', 5);
        }
    }

    my $cmd = $vlan ? "show spanning-tree vlan $vlan" : "show spanning-tree";
    $ssh->send("$cmd\n");
    my $output = $ssh->waitfor('.*[>#]\s*$', $timeout) // '';

    my $root_found = 0;
    my (@blocked, @desg, @root_ports);
    my $tc_count = 0;

    for my $line (split /\n/, $output) {
        if ($line =~ /This bridge is the root/i) {
            output("  [ROOT] This device IS the root bridge\n");
            $root_found = 1;
        }
        if ($line =~ /Root ID.*Priority\s+(\d+)/i || $line =~ /^\s+Priority\s+(\d+)\s+Address\s+(\S+)/i) {
            output("  Root Priority: $1" . ($2 ? "  MAC: $2" : "") . "\n") if $1;
        }
        if ($line =~ /^\s+Address\s+([0-9a-f.:]+)/i && !$root_found) {
            output("  Root MAC: $1\n");
        }
        if ($line =~ /Number of topology changes\s+(\d+)/i) {
            $tc_count = $1;
            my $warn = $tc_count > 10 ? " <== HIGH" : "";
            output("  Topology Changes: $tc_count$warn\n");
        }
        if ($line =~ /^\s*(\S+)\s+(\S+)\s+(\S+)\s+(BLK|BLOCK)\s*/i) {
            push @blocked, $1;
        }
        if ($line =~ /^\s*(\S+)\s+\S+\s+\S+\s+FWD\s+Desg/i) {
            push @desg, $1;
        }
        if ($line =~ /^\s*(\S+)\s+\S+\s+\S+\s+FWD\s+Root/i) {
            push @root_ports, $1;
        }
    }

    output("  Root ports:       " . (@root_ports ? join(', ', @root_ports) : 'none') . "\n");
    output("  Designated ports: " . scalar(@desg) . " total\n");
    if (@blocked) {
        output("  BLOCKED ports:    " . join(', ', @blocked) . "\n");
    } else {
        output("  Blocked ports:    none\n");
    }

    $ssh->send("exit\n");
    $ssh->close();
}

output("STP Audit Report\n");
output("Devices: " . scalar(@devices) . "  VLAN filter: " . ($vlan // 'all') . "\n");

for my $dev (@devices) {
    eval { audit_device($dev) };
    output("ERROR: $dev: $@\n") if $@;
}

output("\nAudit complete.\n");
close $log_fh if $log_fh;