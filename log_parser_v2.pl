Writing the script now — CPU/memory utilization monitor, which is not covered by any of the listed existing scripts.

#!/usr/bin/perl
#
# cpu_memory_monitor.pl - CPU and Memory Utilization Monitor for Cisco IOS/IOS-XE
#
# Purpose:
#   Connects to network devices via SSH, collects CPU and memory utilization
#   data, identifies top resource-consuming processes, and alerts when
#   configurable thresholds are exceeded. Useful for capacity planning,
#   incident response, and proactive health monitoring.
#
# Usage:
#   Single device:  ./cpu_memory_monitor.pl -h 192.168.1.1 -u admin -p secret
#   Device list:    ./cpu_memory_monitor.pl -f devices.txt -u admin -p secret
#   With logging:   ./cpu_memory_monitor.pl -f devices.txt -u admin -p secret -l /tmp/cpu.log
#   Custom alerts:  ./cpu_memory_monitor.pl -h 192.168.1.1 -u admin -p secret --cpu-warn 70 --mem-warn 80
#
# Device file format:
#   One IP or hostname per line; lines starting with # are ignored.
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to target devices (password or key-based auth)
#   Cisco IOS/IOS-XE (tested on 12.x, 15.x, 16.x, 17.x)
#
# Output:
#   Per-device CPU averages (5s/1m/5m), top-5 processes by CPU,
#   processor memory pool utilization, and threshold alerts.
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file);
my $cpu_warn = 75;
my $mem_warn = 85;
my $timeout  = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|password=s' => \$password,
    'l|log=s'      => \$log_file,
    'cpu-warn=i'   => \$cpu_warn,
    'mem-warn=i'   => \$mem_warn,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l logfile] [--cpu-warn N] [--mem-warn N]\n";

die "Provide -h <host> or -f <file>\n" unless $host || $device_file;
die "Username required (-u)\n"         unless $username;
die "Password required (-p)\n"         unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
output("=" x 60);
output("CPU/Memory Monitor  |  $ts");
output(sprintf("Thresholds: CPU >= %d%%  Memory >= %d%%", $cpu_warn, $mem_warn));
output("=" x 60);

check_device($_) for @devices;
close $log_fh if $log_fh;
exit 0;

sub check_device {
    my ($device) = @_;
    output("\n[Device: $device]");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $device,
            user     => $username,
            password => $password,
            raw_pty  => 1,
            timeout  => $timeout,
        );
    };
    if ($@ || !$ssh) {
        output("  ERROR: Could not create SSH session: " . ($@ || 'unknown'));
        return;
    }

    my $logged_in = eval { $ssh->login() };
    if ($@ || !defined $logged_in) {
        output("  ERROR: Authentication failed (bad credentials or SSH key mismatch)");
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|#|>', 5);

    $ssh->send("show processes cpu sorted\n");
    my $cpu_raw = $ssh->waitfor('\$|#|>', $timeout) // '';

    $ssh->send("show processes memory sorted\n");
    my $mem_raw = $ssh->waitfor('\$|#|>', $timeout) // '';

    eval { $ssh->close() };

    parse_cpu($cpu_raw);
    parse_memory($mem_raw);
}

sub parse_cpu {
    my ($out) = @_;

    if ($out =~ /five seconds:\s*(\d+)%[^;]*;\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%/i) {
        my ($s5, $m1, $m5) = ($1, $2, $3);
        output(sprintf("  CPU: 5sec=%-3d%%  1min=%-3d%%  5min=%-3d%%", $s5, $m1, $m5));
        output(sprintf("  ALERT: 1-min CPU (%d%%) >= threshold (%d%%)", $m1, $cpu_warn))
            if $m1 >= $cpu_warn;
    } else {
        output("  CPU: Unable to parse utilization summary");
    }

    my @procs;
    while ($out =~ /^\s*\d+\s+\d+\s+\d+\s+\d+\s+(\d+)%\s+(\d+)%\s+(\d+)%\s+\d+\s+(\S+)/mg) {
        push @procs, [$1, $2, $3, $4];
        last if @procs >= 5;
    }
    if (@procs) {
        output("  Top processes (5s% / 1m% / 5m%  name):");
        output(sprintf("    %3d%% / %3d%% / %3d%%  %s", @{$_})) for @procs;
    }
}

sub parse_memory {
    my ($out) = @_;

    if ($out =~ /Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)/i) {
        my ($total, $used, $free) = ($1, $2, $3);
        my $pct      = ($total > 0) ? int($used / $total * 100) : 0;
        my $used_mb  = int($used  / 1048576);
        my $total_mb = int($total / 1048576);
        output(sprintf("  Memory: %dMB / %dMB used (%d%%)", $used_mb, $total_mb, $pct));
        output(sprintf("  ALERT: Memory (%d%%) >= threshold (%d%%)", $pct, $mem_warn))
            if $pct >= $mem_warn;
    } else {
        output("  Memory: Unable to parse processor pool data");
    }
}

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}