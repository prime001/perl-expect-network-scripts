```perl
#!/usr/bin/perl
#
# hardware_health.pl - Network Device Hardware Health Check
#
# Purpose:
#   Collects CPU utilization, memory usage, temperature sensors, and
#   environmental/power supply status from Cisco IOS/IOS-XE devices.
#   Flags values that exceed warning or critical thresholds.
#
# Usage:
#   Single device:  ./hardware_health.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./hardware_health.pl -f devices.txt -u admin -p secret
#   With log:       ./hardware_health.pl -h 192.168.1.1 -u admin -p secret -l health.log
#
# Prerequisites:
#   cpan Net::SSH::Expect
#
# Device file format (one IP or hostname per line, blank lines/# ignored):
#   192.168.1.1
#   192.168.1.2
#   # core-sw01

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $device_file, $username, $password, $log_file);
my $timeout = 20;
my $CPU_WARN = 70;
my $CPU_CRIT = 90;
my $MEM_WARN = 75;
my $MEM_CRIT = 90;

GetOptions(
    'h|host=s'     => \$host_arg,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$log_file,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOGFILE] [-t TIMEOUT]\n";

die "Provide -h HOST or -f FILE\n" unless $host_arg || $device_file;
die "Username required (-u)\n" unless $username;
die "Password required (-p)\n" unless $password;

my @devices;
if ($host_arg) {
    push @devices, $host_arg;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^\s*#/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

sub log_out {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub check_threshold {
    my ($label, $val, $warn, $crit) = @_;
    return "CRIT" if $val >= $crit;
    return "WARN" if $val >= $warn;
    return "OK";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
log_out("=" x 60 . "\n");
log_out("Hardware Health Check  $timestamp\n");
log_out("=" x 60 . "\n");

for my $host (@devices) {
    log_out("\n--- $host ---\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $host,
            user        => $username,
            password    => $password,
            raw_pty     => 1,
            timeout     => $timeout,
            ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
    };
    if ($@ || !$ssh) {
        log_out("  ERROR: Failed to create SSH session: $@\n");
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !$login) {
        log_out("  ERROR: Authentication failed or connection refused\n");
        next;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#|\>', 5);

    # CPU utilization
    $ssh->send("show processes cpu | include CPU utilization");
    my $cpu_out = $ssh->waitfor('\$|#|\>', $timeout);
    if ($cpu_out && $cpu_out =~ /CPU utilization.*?(\d+)%\/(\d+)%.*?(\d+)%/) {
        my ($five_sec, $one_min, $five_min) = ($1, $2, $3);
        my $status = check_threshold("CPU", $one_min, $CPU_WARN, $CPU_CRIT);
        log_out("  CPU: 5sec=${five_sec}%  1min=${one_min}%  5min=${five_min}%  [$status]\n");
    } else {
        log_out("  CPU: could not parse output\n");
    }

    # Memory utilization
    $ssh->send("show processes memory | include Processor");
    my $mem_out = $ssh->waitfor('\$|#|\>', $timeout);
    if ($mem_out && $mem_out =~ /Processor\s+\S+\s+(\d+)\s+(\d+)/) {
        my ($used, $free) = ($1, $2);
        my $total = $used + $free;
        my $pct = $total > 0 ? int($used / $total * 100) : 0;
        my $status = check_threshold("MEM", $pct, $MEM_WARN, $MEM_CRIT);
        log_out(sprintf("  Memory: used=%dK  free=%dK  util=%d%%  [%s]\n",
            $used/1024, $free/1024, $pct, $status));
    } else {
        log_out("  Memory: could not parse output\n");
    }

    # Temperature and environment
    $ssh->send("show environment temperature");
    my $env_out = $ssh->waitfor('\$|#|\>', $timeout);
    if ($env_out && $env_out =~ /\d+\s+Celsius/i) {
        while ($env_out =~ /(\S+)\s+(\d+)\s+Celsius.*?(Normal|Critical|Warning)/gi) {
            log_out("  Temp $1: ${2}C  [$3]\n");
        }
    } else {
        $ssh->send("show environment all | include Temperature|TEMP");
        my $env2 = $ssh->waitfor('\$|#|\>', $timeout);
        if ($env2 && $env2 =~ /\d+\s*(Celsius|degrees)/i) {
            log_out("  Temp: $env2\n");
        } else {
            log_out("  Temperature: not supported or no data\n");
        }
    }

    # Power supply
    $ssh->send("show environment power | include Power|power");
    my $pwr_out = $ssh->waitfor('\$|#|\>', $timeout);
    if ($pwr_out && $pwr_out =~ /Power/i) {
        my @pwr_lines = grep { /Power.*(?:Good|OK|Fail|Absent|Present)/i }
                        split(/\n/, $pwr_out);
        if (@pwr_lines) {
            log_out("  Power: $_\n") for map { s/^\s+|\s+$//gr } @pwr_lines;
        } else {
            log_out("  Power: no status lines matched\n");
        }
    } else {
        log_out("  Power: not supported or no data\n");
    }

    $ssh->send("exit");
    $ssh->close() if $ssh->can('close');
}

log_out("\nDone.\n");
close $log_fh if $log_fh;
```