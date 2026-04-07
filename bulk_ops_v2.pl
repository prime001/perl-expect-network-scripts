```perl
#!/usr/bin/perl
#
# cpu_memory_health.pl - Bulk CPU and Memory Health Check for Network Devices
#
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE devices via SSH and collects
#   CPU utilization (5-second, 1-minute, 5-minute intervals) and memory
#   usage statistics. Flags devices exceeding configurable thresholds.
#
# Usage:
#   Single device:  ./cpu_memory_health.pl -h 192.168.1.1
#   Device file:    ./cpu_memory_health.pl -f devices.txt
#   With logging:   ./cpu_memory_health.pl -f devices.txt -l health_report.log
#   Custom thresholds: ./cpu_memory_health.pl -f devices.txt --cpu-warn 70 --mem-warn 80
#
# Device file format (one per line, optionally with credentials):
#   192.168.1.1
#   router2.example.com
#   10.0.0.1 admin mypassword
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH key-based auth recommended; password auth supported via env vars or device file
#   ROUTER_USER and ROUTER_PASS environment variables as fallback credentials
#
# Exit codes: 0=all OK, 1=warnings found, 2=errors/unreachable devices

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my $DEFAULT_USER    = $ENV{ROUTER_USER} // 'admin';
my $DEFAULT_PASS    = $ENV{ROUTER_PASS} // '';
my $CPU_WARN_PCT    = 75;
my $MEM_WARN_PCT    = 85;
my $SSH_TIMEOUT     = 15;

my ($opt_host, $opt_file, $opt_log);
GetOptions(
    'h|host=s'     => \$opt_host,
    'f|file=s'     => \$opt_file,
    'l|log=s'      => \$opt_log,
    'cpu-warn=i'   => \$CPU_WARN_PCT,
    'mem-warn=i'   => \$MEM_WARN_PCT,
) or die "Usage: $0 [-h host | -f file] [-l logfile] [--cpu-warn N] [--mem-warn N]\n";

die "Specify -h <host> or -f <file>\n" unless $opt_host || $opt_file;

my @devices;
if ($opt_host) {
    push @devices, { host => $opt_host, user => $DEFAULT_USER, pass => $DEFAULT_PASS };
}
if ($opt_file) {
    open my $fh, '<', $opt_file or die "Cannot open $opt_file: $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g; next unless $_;
        my ($host, $user, $pass) = split /\s+/, $_;
        push @devices, {
            host => $host,
            user => $user // $DEFAULT_USER,
            pass => $pass // $DEFAULT_PASS,
        };
    }
    close $fh;
}

my $log_fh;
if ($opt_log) {
    open $log_fh, '>', $opt_log or die "Cannot open log $opt_log: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $header = sprintf("%-20s %-10s %-10s %-10s %-12s %-12s %s",
    'HOST', 'CPU-5s%', 'CPU-1m%', 'CPU-5m%', 'MEM-USED%', 'MEM-FREE-KB', 'STATUS');
emit("=== CPU/Memory Health Report - $timestamp ===");
emit($header);
emit('-' x length($header));

my ($warn_count, $err_count) = (0, 0);

for my $dev (@devices) {
    my ($host, $user, $pass) = @{$dev}{qw(host user pass)};
    my $result = check_device($host, $user, $pass);

    if ($result->{error}) {
        emit(sprintf("%-20s %-10s %-10s %-10s %-12s %-12s ERROR: %s",
            $host, '-', '-', '-', '-', '-', $result->{error}));
        $err_count++;
        next;
    }

    my $status = 'OK';
    $status = 'WARN-CPU'  if $result->{cpu_1m} >= $CPU_WARN_PCT;
    $status = 'WARN-MEM'  if $result->{mem_pct} >= $MEM_WARN_PCT;
    $status = 'WARN-BOTH' if $result->{cpu_1m} >= $CPU_WARN_PCT && $result->{mem_pct} >= $MEM_WARN_PCT;
    $warn_count++ if $status ne 'OK';

    emit(sprintf("%-20s %-10s %-10s %-10s %-12s %-12s %s",
        $host,
        "$result->{cpu_5s}%",
        "$result->{cpu_1m}%",
        "$result->{cpu_5m}%",
        "$result->{mem_pct}%",
        $result->{mem_free_kb},
        $status));
}

emit('-' x length($header));
emit("Summary: " . scalar(@devices) . " devices | Warnings: $warn_count | Errors: $err_count");
close $log_fh if $log_fh;

exit 2 if $err_count && !$warn_count;
exit 1 if $warn_count;
exit 0;

sub check_device {
    my ($host, $user, $pass) = @_;

    my $ssh = eval {
        Net::SSH::Expect->new(
            host       => $host,
            user       => $user,
            password   => $pass,
            raw_pty    => 1,
            timeout    => $SSH_TIMEOUT,
        );
    };
    return { error => "SSH init failed: $@" } if $@;

    my $login = eval { $ssh->login() };
    return { error => "Login failed: $@" } if $@ || !$login;

    $ssh->send('terminal length 0');
    $ssh->waitfor('\$\s*$|#\s*$', 5);

    $ssh->send('show processes cpu | include CPU');
    my $cpu_out = $ssh->waitfor('#\s*$', 10) // '';

    $ssh->send('show processes memory | include Processor');
    my $mem_out = $ssh->waitfor('#\s*$', 10) // '';

    $ssh->send('exit');

    my ($cpu_5s, $cpu_1m, $cpu_5m) = (0, 0, 0);
    if ($cpu_out =~ /CPU utilization.*?(\d+)%.*?(\d+)%.*?(\d+)%/i) {
        ($cpu_5s, $cpu_1m, $cpu_5m) = ($1, $2, $3);
    } else {
        return { error => 'Could not parse CPU output' };
    }

    my ($mem_used, $mem_free, $mem_pct) = (0, 0, 0);
    if ($mem_out =~ /(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/i) {
        $mem_used = $2;
        $mem_free = $3;
        $mem_pct  = int($mem_used / ($mem_used + $mem_free) * 100) if ($mem_used + $mem_free) > 0;
    } else {
        return { error => 'Could not parse memory output' };
    }

    return {
        cpu_5s     => $cpu_5s,
        cpu_1m     => $cpu_1m,
        cpu_5m     => $cpu_5m,
        mem_pct    => $mem_pct,
        mem_free_kb => int($mem_free / 1024),
    };
}

sub emit {
    my $line = shift;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}
```