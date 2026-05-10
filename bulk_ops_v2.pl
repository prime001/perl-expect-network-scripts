#!/usr/bin/perl
#
# cpu_mem_check.pl - Cisco IOS CPU and Memory Utilization Health Check
#
# PURPOSE:
#   Connects to one or more Cisco IOS/IOS-XE devices and collects CPU load
#   (5-sec, 1-min, 5-min) plus processor memory utilization. Flags devices
#   that exceed configurable thresholds so operators can act before outages.
#
# USAGE:
#   Single device:    ./cpu_mem_check.pl -h 192.168.1.1 -u admin -p secret
#   Device list file: ./cpu_mem_check.pl -f devices.txt -u admin -p secret
#   With log output:  ./cpu_mem_check.pl -f devices.txt -u admin -p secret -l health.log
#   Custom threshold: ./cpu_mem_check.pl -f devices.txt -u admin -p secret --cpu-warn 70 --mem-warn 85
#
# DEVICE FILE FORMAT (one IP or hostname per line, blank lines and # ignored):
#   192.168.1.1
#   192.168.1.2
#   core-router-01
#
# PREREQUISITES:
#   cpan Net::SSH::Expect Getopt::Long
#   SSH key auth or password auth must work for the target user account.
#
# EXIT CODES:
#   0 - All devices within thresholds
#   1 - One or more devices exceeded threshold or had connection errors

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log);
my $cpu_warn = 80;
my $mem_warn = 90;
my $timeout  = 20;

GetOptions(
    'h|host=s'     => \$opt_host,
    'f|file=s'     => \$opt_file,
    'u|user=s'     => \$opt_user,
    'p|pass=s'     => \$opt_pass,
    'l|log=s'      => \$opt_log,
    'cpu-warn=i'   => \$cpu_warn,
    'mem-warn=i'   => \$mem_warn,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 [-h host|-f file] -u user -p pass [-l logfile] [--cpu-warn N] [--mem-warn N]\n";

die "ERROR: Provide -h HOST or -f FILE\n"  unless $opt_host || $opt_file;
die "ERROR: -u USER is required\n"         unless $opt_user;
die "ERROR: -p PASS is required\n"         unless $opt_pass;

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open my $fh, '<', $opt_file or die "Cannot open $opt_file: $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if length }
    close $fh;
}

my $log_fh;
if ($opt_log) {
    open $log_fh, '>', $opt_log or die "Cannot open log $opt_log: $!\n";
}

sub out {
    print @_;
    print $log_fh @_ if $log_fh;
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=" x 72 . "\n");
out("CPU/Memory Health Check  |  $ts\n");
out(sprintf("Thresholds: CPU >= %d%%  |  Memory >= %d%%\n", $cpu_warn, $mem_warn));
out("=" x 72 . "\n");
out(sprintf("%-20s  %6s %6s %6s  %7s  %s\n", 'Device', '5sec%', '1min%', '5min%', 'Mem%', 'Status'));
out("-" x 72 . "\n");

my $exit_code = 0;

for my $host (@devices) {
    my ($cpu5s, $cpu1m, $cpu5m, $mem_pct) = (undef, undef, undef, undef);
    my $status = 'OK';

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $host,
            user        => $opt_user,
            password    => $opt_pass,
            raw_pty     => 1,
            timeout     => $timeout,
            ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
    };
    if ($@ || !$ssh) { out(sprintf("%-20s  %s\n", $host, "CONNECT ERROR: $@")); $exit_code = 1; next }

    my $login_ok = eval { $ssh->login() };
    if ($@ || !$login_ok) { out(sprintf("%-20s  %s\n", $host, "AUTH ERROR")); $exit_code = 1; next }

    $ssh->exec('terminal length 0');

    my $cpu_out = $ssh->exec('show processes cpu sorted | head lines 5');
    if ($cpu_out =~ /CPU utilization for five seconds:\s*(\d+)%.*?one minute:\s*(\d+)%.*?five minutes:\s*(\d+)%/s) {
        ($cpu5s, $cpu1m, $cpu5m) = ($1, $2, $3);
    }

    my $ver_out = $ssh->exec('show version | include bytes of memory');
    if ($ver_out =~ /(\d+)K\/(\d+)K bytes of memory/) {
        my $total = $1 + $2;
        $mem_pct = int($1 / $total * 100) if $total > 0;
    } elsif ($ver_out =~ /(\d+) bytes of physical memory/) {
        my $mem2 = $ssh->exec('show processes memory sorted | head lines 3');
        if ($mem2 =~ /Processor\s+\d+\s+(\d+)\s+(\d+)/) {
            my $used = $1; my $free = $2;
            my $total = $used + $free;
            $mem_pct = int($used / $total * 100) if $total > 0;
        }
    }

    $ssh->exec('exit');

    my $alert = '';
    if (defined $cpu5m && $cpu5m >= $cpu_warn) { $status = 'WARN-CPU'; $alert .= " cpu5m=${cpu5m}%"; $exit_code = 1 }
    if (defined $mem_pct && $mem_pct >= $mem_warn) { $status = 'WARN-MEM'; $alert .= " mem=${mem_pct}%"; $exit_code = 1 }

    out(sprintf("%-20s  %6s %6s %6s  %7s  %s%s\n",
        $host,
        defined $cpu5s  ? "${cpu5s}%"  : 'N/A',
        defined $cpu1m  ? "${cpu1m}%"  : 'N/A',
        defined $cpu5m  ? "${cpu5m}%"  : 'N/A',
        defined $mem_pct ? "${mem_pct}%" : 'N/A',
        $status, $alert));
}

out("-" x 72 . "\n");
out(sprintf("Checked %d device(s)  |  Exit: %s\n", scalar @devices, $exit_code ? 'WARN' : 'OK'));
close $log_fh if $log_fh;
exit $exit_code;