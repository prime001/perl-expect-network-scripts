#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# cpu_memory_health.pl - Network Device CPU/Memory Health Monitor
# =============================================================================
# Purpose:
#   Connects to Cisco IOS/IOS-XE network devices via SSH and collects CPU
#   utilization (5s/1m/5m intervals) and memory pool statistics. Flags devices
#   exceeding configurable thresholds. Designed for NOC health checks and
#   capacity planning data collection.
#
# Usage:
#   Single device:  ./cpu_memory_health.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./cpu_memory_health.pl -f devices.txt -u admin -p secret
#   With logging:   ./cpu_memory_health.pl -f devices.txt -u admin -p secret -l health.log
#   Custom thresh:  ./cpu_memory_health.pl -h 10.0.0.1 -u admin -p secret --cpu-warn 70 --mem-warn 80
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH key-based auth or password auth (--password flag)
#   Target devices must have SSH enabled and user must have priv 1+
#
# Output:
#   Tabular summary per device with WARN/OK/FAIL status indicators
# =============================================================================

my ($host, $device_file, $username, $password, $logfile);
my $cpu_warn   = 75;
my $mem_warn   = 85;
my $timeout    = 15;
my $prompt     = '#';

GetOptions(
    'h|host=s'      => \$host,
    'f|file=s'      => \$device_file,
    'u|user=s'      => \$username,
    'p|password=s'  => \$password,
    'l|log=s'       => \$logfile,
    'cpu-warn=i'    => \$cpu_warn,
    'mem-warn=i'    => \$mem_warn,
    't|timeout=i'   => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l logfile]\n";

die "ERROR: Provide -h <host> or -f <file>\n" unless $host || $device_file;
die "ERROR: Username required (-u)\n" unless $username;
die "ERROR: Password required (-p)\n" unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        s/#.*//;
        s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close($fh);
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log $logfile: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $header = sprintf("%-20s %-8s %-8s %-8s %-12s %-12s %-6s",
    'DEVICE', 'CPU-5s', 'CPU-1m', 'CPU-5m', 'MEM-USED%', 'MEM-FREE', 'STATUS');
output("=" x 78);
output("CPU/Memory Health Check  |  $timestamp");
output("Thresholds: CPU warn >=$cpu_warn%  |  Mem warn >=$mem_warn%");
output("=" x 78);
output($header);
output("-" x 78);

for my $device (@devices) {
    check_device($device);
}

output("=" x 78);
close($log_fh) if $log_fh;

sub check_device {
    my ($dev) = @_;
    my $ssh;

    eval {
        $ssh = Net::SSH::Expect->new(
            host        => $dev,
            user        => $username,
            password    => $password,
            raw_pty     => 1,
            timeout     => $timeout,
            ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
        $ssh->login();
    };
    if ($@) {
        my $err = $@;
        $err =~ s/\n.*//s;
        output(sprintf("%-20s %-42s FAIL - %s", $dev, '', $err));
        return;
    }

    # Disable paging
    $ssh->send("terminal length 0");
    $ssh->waitfor("$prompt\\s*\$", $timeout);

    # Collect CPU stats
    $ssh->send("show processes cpu | include CPU utilization");
    my $cpu_raw = $ssh->waitfor("$prompt\\s*\$", $timeout) // '';

    my ($cpu5s, $cpu1m, $cpu5m) = ('?', '?', '?');
    if ($cpu_raw =~ /(\d+)%\/\d+%;\s+one minute:\s+(\d+)%;\s+five minutes:\s+(\d+)%/) {
        ($cpu5s, $cpu1m, $cpu5m) = ($1, $2, $3);
    }

    # Collect memory stats
    $ssh->send("show processes memory | include Processor");
    my $mem_raw = $ssh->waitfor("$prompt\\s*\$", $timeout) // '';

    my ($mem_used_pct, $mem_free_kb) = ('?', '?');
    if ($mem_raw =~ /Processor\s+\d+\s+(\d+)\s+(\d+)/) {
        my ($used, $free) = ($1, $2);
        my $total = $used + $free;
        if ($total > 0) {
            $mem_used_pct = int(($used / $total) * 100);
            $mem_free_kb  = int($free / 1024) . 'M';
        }
    }

    $ssh->send("exit");

    my $status = 'OK';
    if ($cpu5s eq '?' && $mem_used_pct eq '?') {
        $status = 'PARSE-ERR';
    } else {
        $status = 'WARN' if ($cpu5s  ne '?' && $cpu5s  >= $cpu_warn);
        $status = 'WARN' if ($cpu1m  ne '?' && $cpu1m  >= $cpu_warn);
        $status = 'WARN' if ($mem_used_pct ne '?' && $mem_used_pct >= $mem_warn);
    }

    output(sprintf("%-20s %-8s %-8s %-8s %-12s %-12s %-6s",
        $dev,
        "${cpu5s}%", "${cpu1m}%", "${cpu5m}%",
        "${mem_used_pct}%",
        $mem_free_kb,
        $status
    ));
}

sub output {
    my ($line) = @_;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}