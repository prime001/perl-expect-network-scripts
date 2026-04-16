```perl
#!/usr/bin/perl
# =============================================================================
# cpu_memory_health.pl - CPU, Memory & Environment Health Check
# =============================================================================
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE devices and collects CPU
#   utilization, memory usage, and environment alarms (temperature, power,
#   fans). Flags devices exceeding configurable thresholds.
#
# Usage:
#   Single device:  ./cpu_memory_health.pl -h 192.168.1.1
#   Device list:    ./cpu_memory_health.pl -f devices.txt
#   With logging:   ./cpu_memory_health.pl -f devices.txt -l health.log
#   Custom thresh:  ./cpu_memory_health.pl -f devices.txt -c 70 -m 80
#
# Options:
#   -h HOST    Single device IP or hostname
#   -f FILE    File with one device per line (# comments supported)
#   -u USER    SSH username (default: $NET_USER env or 'admin')
#   -p PASS    SSH password (default: $NET_PASS env)
#   -l FILE    Log file path (optional)
#   -c INT     CPU warning threshold % (default: 75)
#   -m INT     Memory warning threshold % (default: 85)
#   -t INT     SSH timeout in seconds (default: 30)
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   cpan Getopt::Long
#
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($host, $file, $logfile);
my $username  = $ENV{NET_USER} || 'admin';
my $password  = $ENV{NET_PASS} || '';
my $cpu_warn  = 75;
my $mem_warn  = 85;
my $timeout   = 30;

GetOptions(
    'h=s' => \$host,
    'f=s' => \$file,
    'u=s' => \$username,
    'p=s' => \$password,
    'l=s' => \$logfile,
    'c=i' => \$cpu_warn,
    'm=i' => \$mem_warn,
    't=i' => \$timeout,
) or die "Usage: $0 [-h host | -f file] [-u user] [-p pass] [-l logfile] [-c cpu%] [-m mem%]\n";

die "ERROR: Specify -h HOST or -f FILE\n" unless $host || $file;
die "ERROR: Password required (-p or \$NET_PASS)\n" unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $file) or die "ERROR: Cannot open $file: $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
}

my $LOG;
if ($logfile) {
    open($LOG, '>>', $logfile) or die "ERROR: Cannot open log $logfile: $!\n";
}

sub log_print {
    my ($msg) = @_;
    print $msg;
    print $LOG $msg if $LOG;
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
log_print("=" x 70 . "\n");
log_print("CPU/Memory/Environment Health Check - $ts\n");
log_print("Thresholds: CPU>=${cpu_warn}%  Memory>=${mem_warn}%\n");
log_print("=" x 70 . "\n\n");

my ($ok_count, $warn_count, $fail_count) = (0, 0, 0);

for my $device (@devices) {
    log_print("--- $device ---\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $device,
            user        => $username,
            password    => $password,
            raw_pty     => 1,
            timeout     => $timeout,
        );
    };
    if ($@ || !$ssh) {
        log_print("  FAIL: Cannot create SSH session: $@\n\n");
        $fail_count++;
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        log_print("  FAIL: Authentication failed or connection refused\n\n");
        $fail_count++;
        next;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|#', 10);

    my $warned = 0;

    # CPU check
    $ssh->send("show processes cpu | include CPU\n");
    my $cpu_out = $ssh->waitfor('#', $timeout);
    if ($cpu_out && $cpu_out =~ /CPU utilization.*?(\d+)%\/(\d+)%\/(\d+)%/) {
        my ($five_sec, $one_min, $five_min) = ($1, $2, $3);
        my $flag = ($one_min >= $cpu_warn) ? " [WARN]" : "";
        $warned++ if $flag;
        log_print("  CPU   5s:${five_sec}% 1m:${one_min}% 5m:${five_min}%${flag}\n");
    } else {
        log_print("  CPU   (could not parse)\n");
    }

    # Memory check
    $ssh->send("show processes memory | include Processor\n");
    my $mem_out = $ssh->waitfor('#', $timeout);
    if ($mem_out && $mem_out =~ /(\d+)\s+(\d+)\s+(\d+)/) {
        my ($total, $used, $free) = ($1, $2, $3);
        my $pct = int($used / $total * 100);
        my $flag = ($pct >= $mem_warn) ? " [WARN]" : "";
        $warned++ if $flag;
        my $used_mb = int($used / 1048576);
        my $free_mb = int($free / 1048576);
        log_print("  MEM   ${pct}% used (${used_mb}MB used / ${free_mb}MB free)${flag}\n");
    } else {
        log_print("  MEM   (could not parse)\n");
    }

    # Environment alarms
    $ssh->send("show environment all | include FAIL|WARN|Critical|Shutdown|Inlet\n");
    my $env_out = $ssh->waitfor('#', $timeout);
    my @alarms;
    if ($env_out) {
        for my $line (split /\n/, $env_out) {
            next if $line =~ /show environment|^\s*$/;
            chomp $line;
            if ($line =~ /FAIL|WARN|Critical|Shutdown/i) {
                push @alarms, "  ENV   ALARM: $line";
                $warned++;
            } elsif ($line =~ /Inlet.*?(\d+)\s+Celsius/i) {
                push @alarms, "  ENV   Inlet temp: $1C";
            }
        }
    }
    if (@alarms) {
        log_print("$_\n") for @alarms;
    } else {
        log_print("  ENV   No alarms\n");
    }

    $ssh->close() if $ssh->can('close');

    if ($warned) {
        $warn_count++;
    } else {
        $ok_count++;
    }
    log_print("\n");
}

log_print("=" x 70 . "\n");
log_print(sprintf("Summary: %d OK  %d WARNING  %d FAILED  (of %d devices)\n",
    $ok_count, $warn_count, $fail_count, scalar @devices));
log_print("=" x 70 . "\n");

close $LOG if $LOG;
exit(($warn_count + $fail_count > 0) ? 1 : 0);
```