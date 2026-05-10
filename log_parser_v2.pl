#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# cpu_mem_health.pl — Cisco IOS CPU & Memory Health Checker
#
# Purpose:
#   Connects to one or more Cisco IOS devices via SSH and collects CPU
#   utilization (5s/1m/5m) and processor memory (used/free). Flags any
#   device exceeding configurable thresholds and exits non-zero if any
#   threshold is breached — useful for cron-based alerting.
#
# Usage:
#   ./cpu_mem_health.pl -h 192.168.1.1 -u admin -p secret
#   ./cpu_mem_health.pl -f devices.txt -u admin -p secret -l health.log
#   ./cpu_mem_health.pl -h core-sw1 -u admin -p secret --cpu-warn 70 --mem-warn 80
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH key-based auth or password. Devices must have 'ip ssh' enabled.
#
# Device file format: one hostname or IP per line, blank lines/# comments ok.
# =============================================================================

my ($host, $device_file, $username, $password, $log_file);
my $timeout   = 15;
my $cpu_warn  = 80;   # percent
my $mem_warn  = 85;   # percent
my $enable_pw = '';

GetOptions(
    'h|host=s'      => \$host,
    'f|file=s'      => \$device_file,
    'u|user=s'      => \$username,
    'p|pass=s'      => \$password,
    'e|enable=s'    => \$enable_pw,
    'l|log=s'       => \$log_file,
    't|timeout=i'   => \$timeout,
    'cpu-warn=i'    => \$cpu_warn,
    'mem-warn=i'    => \$mem_warn,
) or die "Usage: $0 -h HOST | -f FILE -u USER -p PASS [-l logfile]\n";

die "Provide -h HOST or -f FILE\n"  unless $host || $device_file;
die "Provide -u USERNAME\n"         unless $username;
die "Provide -p PASSWORD\n"         unless $password;

my @devices = $host ? ($host) : load_devices($device_file);
die "No devices to check\n" unless @devices;

my $LOG;
if ($log_file) {
    open($LOG, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

my $timestamp  = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $any_breach = 0;

log_print("=== CPU/Memory Health Check — $timestamp ===");

for my $device (@devices) {
    check_device($device);
}

log_print("=== Done. Threshold breaches: $any_breach ===");
close($LOG) if $LOG;
exit($any_breach ? 1 : 0);

# -----------------------------------------------------------------------------

sub check_device {
    my ($dev) = @_;
    log_print("\n[$dev] Connecting...");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $dev,
            user        => $username,
            password    => $password,
            raw_pty     => 1,
            timeout     => $timeout,
        );
    };
    if ($@ || !$ssh) {
        log_print("[$dev] ERROR: Could not create SSH object: $@");
        $any_breach++;
        return;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        log_print("[$dev] ERROR: Login failed (auth error or timeout)");
        $any_breach++;
        return;
    }

    # Handle enable mode if password provided
    if ($enable_pw) {
        $ssh->send("enable");
        $ssh->waitfor('Password:', 5) or do {
            log_print("[$dev] ERROR: Enable prompt not seen");
            return;
        };
        $ssh->send($enable_pw);
        $ssh->waitfor('#', 5);
    }

    # Disable pagination
    $ssh->exec("terminal length 0");

    # --- CPU ---
    my $cpu_out = $ssh->exec("show processes cpu | include CPU utilization");
    my ($cpu_5s, $cpu_1m, $cpu_5m);
    if ($cpu_out =~ /CPU utilization.*?(\d+)%\/(\d+)%.*?(\d+)%.*?(\d+)%/) {
        ($cpu_5s, $cpu_1m, $cpu_5m) = ($1, $3, $4);
    } elsif ($cpu_out =~ /(\d+)%.*?(\d+)%.*?(\d+)%/) {
        ($cpu_5s, $cpu_1m, $cpu_5m) = ($1, $2, $3);
    } else {
        log_print("[$dev] WARN: Could not parse CPU output");
        $cpu_5s = $cpu_1m = $cpu_5m = -1;
    }

    # --- Memory ---
    my $mem_out  = $ssh->exec("show processes memory | include Processor");
    my ($mem_used, $mem_free, $mem_pct);
    if ($mem_out =~ /Processor\s+\S+\s+(\d+)\s+(\d+)/) {
        ($mem_used, $mem_free) = ($1, $2);
        my $total = $mem_used + $mem_free;
        $mem_pct  = $total > 0 ? int(($mem_used / $total) * 100) : -1;
    } else {
        log_print("[$dev] WARN: Could not parse memory output");
        $mem_pct = -1;
    }

    $ssh->close();

    my $cpu_flag = ($cpu_5m >= 0 && $cpu_5m >= $cpu_warn) ? " [!BREACH]" : "";
    my $mem_flag = ($mem_pct  >= 0 && $mem_pct  >= $mem_warn) ? " [!BREACH]" : "";

    $any_breach++ if $cpu_flag || $mem_flag;

    log_print(sprintf("[$dev] CPU: 5s=%s%% 1m=%s%% 5m=%s%%%s",
        $cpu_5s // '?', $cpu_1m // '?', $cpu_5m // '?', $cpu_flag));
    log_print(sprintf("[$dev] MEM: used=%s free=%s pct=%s%%%s",
        fmt_bytes($mem_used), fmt_bytes($mem_free), $mem_pct // '?', $mem_flag));
}

sub load_devices {
    my ($file) = @_;
    open(my $fh, '<', $file) or die "Cannot open device file $file: $!\n";
    my @list = grep { /\S/ && !/^\s*#/ } map { chomp; s/^\s+|\s+$//gr } <$fh>;
    close($fh);
    return @list;
}

sub fmt_bytes {
    my ($n) = @_;
    return '?' unless defined $n;
    return sprintf('%.1fM', $n / 1_048_576) if $n >= 1_048_576;
    return sprintf('%.1fK', $n / 1_024)     if $n >= 1_024;
    return "${n}B";
}

sub log_print {
    my ($msg) = @_;
    print "$msg\n";
    print $LOG "$msg\n" if $LOG;
}