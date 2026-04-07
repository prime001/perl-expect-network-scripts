#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# device_health.pl - Network Device CPU/Memory/Environment Health Check
#
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE devices via SSH and collects
#   CPU utilization, memory usage, and environmental status (temperature,
#   power, fans). Flags any metrics exceeding configurable thresholds.
#
# Usage:
#   ./device_health.pl --host 192.168.1.1 --user admin --pass s3cr3t
#   ./device_health.pl --file devices.txt --user admin --pass s3cr3t --log health.log
#   ./device_health.pl --host router1 --user admin --pass s3cr3t --cpu-warn 70 --mem-warn 80
#
# Prerequisites:
#   cpan Net::SSH::Expect
#
# devices.txt format: one IP or hostname per line, blank lines and # comments ignored
# =============================================================================

my ($host, $device_file, $username, $password, $log_file);
my $cpu_warn    = 75;
my $mem_warn    = 80;
my $timeout     = 30;

GetOptions(
    'host=s'      => \$host,
    'file=s'      => \$device_file,
    'user=s'      => \$username,
    'pass=s'      => \$password,
    'log=s'       => \$log_file,
    'cpu-warn=i'  => \$cpu_warn,
    'mem-warn=i'  => \$mem_warn,
    'timeout=i'   => \$timeout,
) or die "Usage: $0 --host HOST|--file FILE --user USER --pass PASS [--log FILE] [--cpu-warn N] [--mem-warn N]\n";

die "Provide --host or --file\n"   unless $host || $device_file;
die "Provide --user and --pass\n"  unless $username && $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*$/ || /^\s*#/; push @devices, $_; }
    close $fh;
}

my $LOG;
if ($log_file) {
    open($LOG, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

sub out {
    my $msg = shift;
    print $msg;
    print $LOG $msg if $LOG;
}

sub check_device {
    my $dev = shift;
    out("\n" . "="x60 . "\n");
    out("Device : $dev\n");
    out("Time   : " . strftime("%Y-%m-%d %H:%M:%S", localtime) . "\n");
    out("="x60 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $dev,
        user        => $username,
        password    => $password,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        timeout     => $timeout,
        raw_pty     => 1,
    );

    eval { $ssh->run_ssh() or die "SSH failed\n"; };
    if ($@) { out("  [ERROR] Connection failed: $@\n"); return; }

    my $login = $ssh->waitfor('assword:|#|>', 15);
    if (!defined $login) { out("  [ERROR] No login prompt received\n"); return; }
    if ($login =~ /assword:/) {
        $ssh->send($password);
        $ssh->waitfor('#|>', 10) or do { out("  [ERROR] Authentication failed\n"); return; };
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('#', 5);

    # CPU check
    $ssh->send("show processes cpu | include CPU utilization");
    my $cpu_out = $ssh->waitfor('#', 10) // '';
    if ($cpu_out =~ /CPU utilization for five seconds:\s*(\d+)%.*?one minute:\s*(\d+)%.*?five minutes:\s*(\d+)%/) {
        my ($s5, $m1, $m5) = ($1, $2, $3);
        my $flag = ($m5 >= $cpu_warn) ? " [WARN: >= ${cpu_warn}%]" : "";
        out("  CPU  5sec=${s5}%  1min=${m1}%  5min=${m5}%${flag}\n");
    } else {
        out("  CPU  [could not parse]\n");
    }

    # Memory check
    $ssh->send("show processes memory | include Processor");
    my $mem_out = $ssh->waitfor('#', 10) // '';
    if ($mem_out =~ /Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)/) {
        my ($total, $used, $free) = ($1, $2, $3);
        my $pct = ($total > 0) ? int($used / $total * 100) : 0;
        my $flag = ($pct >= $mem_warn) ? " [WARN: >= ${mem_warn}%]" : "";
        out(sprintf("  MEM  total=%dK used=%dK free=%dK (%d%% used)%s\n",
            $total/1024, $used/1024, $free/1024, $pct, $flag));
    } else {
        out("  MEM  [could not parse]\n");
    }

    # Environment (temperature/power/fans) - may not be supported on all platforms
    $ssh->send("show environment all");
    my $env_out = $ssh->waitfor('#', 10) // '';
    my @alarms = ($env_out =~ /^.*(?:CRITICAL|MAJOR|MINOR|WARNING|Fail|fail).*$/gm);
    if (@alarms) {
        out("  ENV  ALARMS DETECTED:\n");
        out("    $_\n") for @alarms;
    } elsif ($env_out =~ /\S/) {
        out("  ENV  No alarms detected\n");
    } else {
        out("  ENV  [not supported or no output]\n");
    }

    # Uptime
    $ssh->send("show version | include uptime");
    my $ver_out = $ssh->waitfor('#', 10) // '';
    if ($ver_out =~ /(uptime is .+)/) {
        out("  UP   $1\n");
    }

    $ssh->send("exit");
    $ssh->close();
}

out("Device Health Check Report\n");
out("CPU warn threshold: ${cpu_warn}%  |  MEM warn threshold: ${mem_warn}%\n");

check_device($_) for @devices;

out("\nDone. " . scalar(@devices) . " device(s) checked.\n");
close $LOG if $LOG;