The prompt says "Output ONLY the script content" — here it is:

#!/usr/bin/perl
# =============================================================================
# cpu_memory_health.pl - Cisco IOS CPU and Memory Health Monitor
#
# Purpose:
#   Connects to one or more Cisco IOS devices via SSH and collects CPU
#   utilization (5-second, 1-minute, 5-minute intervals) and memory
#   utilization (processor pool used/free). Useful for baseline health
#   checks, capacity planning, and pre/post-change verification.
#
# Usage:
#   ./cpu_memory_health.pl -h 192.168.1.1 -u admin -p secret
#   ./cpu_memory_health.pl -f devices.txt -u admin -p secret -l health.log
#   ./cpu_memory_health.pl -h 10.0.0.1 -u admin -p secret -w 80 -c 90
#
# Options:
#   -h <host>      Single device IP or hostname
#   -f <file>      File containing one device per line
#   -u <user>      SSH username
#   -p <pass>      SSH password
#   -e <enable>    Enable password (optional, defaults to SSH password)
#   -l <logfile>   Output log file (optional)
#   -w <pct>       Warning threshold % for CPU/memory (default: 70)
#   -c <pct>       Critical threshold % for CPU/memory (default: 90)
#   -t <secs>      SSH timeout in seconds (default: 30)
#
# Prerequisites:
#   cpan Net::SSH::Expect
#
# Exit codes:
#   0 = all devices OK
#   1 = one or more devices at WARNING or higher
#   2 = connection/auth failure on one or more devices
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);

our %opts;
getopts('h:f:u:p:e:l:w:c:t:', \%opts);

my $host      = $opts{h} // '';
my $file      = $opts{f} // '';
my $user      = $opts{u} or die "Usage: $0 -u <user> -p <pass> [-h <host>|-f <file>]\n";
my $pass      = $opts{p} or die "Usage: $0 -u <user> -p <pass> [-h <host>|-f <file>]\n";
my $enable    = $opts{e} // $pass;
my $logfile   = $opts{l} // '';
my $warn_pct  = $opts{w} // 70;
my $crit_pct  = $opts{c} // 90;
my $timeout   = $opts{t} // 30;

die "Specify -h <host> or -f <file>\n" unless $host || $file;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $file) or die "Cannot open device file '$file': $!\n";
    while (<$fh>) { chomp; push @devices, $_ if /\S/ && !/^#/; }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log file '$logfile': $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
my $exit_code = 0;

sub emit {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub status_label {
    my ($pct, $w, $c) = @_;
    return 'CRIT' if $pct >= $c;
    return 'WARN' if $pct >= $w;
    return 'OK  ';
}

emit("=" x 72 . "\n");
emit("CPU/Memory Health Check  |  $timestamp\n");
emit("=" x 72 . "\n");

for my $dev (@devices) {
    emit("\n--- $dev ---\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $dev,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_output;
    eval { $login_output = $ssh->login(); };
    if ($@ || !defined $login_output) {
        emit("  [ERROR] SSH connection failed: $@\n");
        $exit_code = 2;
        next;
    }

    if ($login_output =~ /[Pp]assword/i) {
        emit("  [ERROR] Authentication failed for $dev\n");
        $exit_code = 2;
        next;
    }

    # Enter enable mode if needed
    if ($login_output =~ />\s*$/) {
        $ssh->send("enable");
        my $en_out = $ssh->waitfor('Password:|#', $timeout);
        if ($en_out =~ /Password:/i) {
            $ssh->send($enable);
            $ssh->waitfor('#', $timeout);
        }
    }

    # Disable paging
    $ssh->exec("terminal length 0");

    # Collect CPU stats
    my $cpu_out = $ssh->exec("show processes cpu | include CPU utilization");
    my ($cpu5s, $cpu1m, $cpu5m) = (0, 0, 0);
    if ($cpu_out =~ /CPU utilization.*?(\d+)%.*?(\d+)%.*?(\d+)%/) {
        ($cpu5s, $cpu1m, $cpu5m) = ($1, $2, $3);
    }

    # Collect memory stats
    my $mem_out = $ssh->exec("show processes memory | include Processor");
    my ($mem_used, $mem_free) = (0, 0);
    if ($mem_out =~ /Processor\s+\S+\s+(\d+)\s+(\d+)/) {
        ($mem_used, $mem_free) = ($1, $2);
    }

    $ssh->close();

    my $mem_total = $mem_used + $mem_free;
    my $mem_pct   = $mem_total > 0 ? int(($mem_used / $mem_total) * 100) : 0;
    my $mem_used_mb = int($mem_used / 1024 / 1024);
    my $mem_free_mb = int($mem_free / 1024 / 1024);

    my $cpu_status = status_label($cpu1m, $warn_pct, $crit_pct);
    my $mem_status = status_label($mem_pct, $warn_pct, $crit_pct);

    emit(sprintf("  CPU  [%s]  5sec: %3d%%  1min: %3d%%  5min: %3d%%\n",
        $cpu_status, $cpu5s, $cpu1m, $cpu5m));
    emit(sprintf("  MEM  [%s]  Used: %4dMB  Free: %4dMB  Util: %3d%%\n",
        $mem_status, $mem_used_mb, $mem_free_mb, $mem_pct));

    $exit_code = 1 if ($exit_code < 2) &&
        ($cpu_status =~ /WARN|CRIT/ || $mem_status =~ /WARN|CRIT/);
}

emit("\n" . "=" x 72 . "\n");
emit(sprintf("Checked %d device(s)  |  Exit: %d (%s)\n",
    scalar @devices, $exit_code,
    $exit_code == 0 ? 'OK' : $exit_code == 1 ? 'WARNING/CRITICAL' : 'CONNECTION ERROR'));
emit("=" x 72 . "\n");

close $log_fh if $log_fh;
exit $exit_code;