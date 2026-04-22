#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# health_check.pl - Network Device CPU/Memory/Environment Health Monitor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE network devices via SSH and collects
#   CPU utilization, memory usage, and environmental sensor data (temperature,
#   fans, power supplies). Flags any values exceeding configurable thresholds
#   and logs results for trending or alerting pipelines.
#
# Usage:
#   ./health_check.pl -h <host> -u <user> -p <pass> [-l <logfile>]
#   ./health_check.pl --hostfile devices.txt -u <user> -p <pass> [-l <logfile>]
#   ./health_check.pl -h 192.168.1.1 -u admin -p secret -l /var/log/net_health.log
#
# Prerequisites:
#   - Net::SSH::Expect (cpan install Net::SSH::Expect)
#   - SSH access enabled on target devices
#   - Read-only or operator-level credentials sufficient
#
# Thresholds (adjust as needed):
#   CPU  5-min avg  > 70% = WARNING, > 90% = CRITICAL
#   Memory free     < 20% = WARNING, < 10% = CRITICAL
# =============================================================================

my ($host, $user, $pass, $hostfile, $logfile, $timeout);
my $cpu_warn  = 70;
my $cpu_crit  = 90;
my $mem_warn  = 20;
my $mem_crit  = 10;

GetOptions(
    'h|host=s'     => \$host,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'f|hostfile=s' => \$hostfile,
    'l|log=s'      => \$logfile,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h <host> -u <user> -p <pass> [-l <logfile>]\n";

$timeout //= 30;
die "ERROR: username and password required\n" unless $user && $pass;
die "ERROR: specify -h <host> or -f <hostfile>\n" unless $host || $hostfile;

my @hosts;
if ($hostfile) {
    open(my $fh, '<', $hostfile) or die "Cannot open hostfile $hostfile: $!\n";
    while (<$fh>) { chomp; push @hosts, $_ if /\S/ && !/^#/; }
    close $fh;
} else {
    @hosts = ($host);
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open logfile $logfile: $!\n";
}

sub log_print {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub check_device {
    my ($device) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    log_print("\n[$ts] === Health Check: $device ===\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_output;
    eval { $login_output = $ssh->login(); };
    if ($@ || !defined $login_output) {
        log_print("  [ERROR] SSH connection failed: $@\n");
        return;
    }
    if ($login_output =~ /(?:denied|incorrect|failed)/i) {
        log_print("  [ERROR] Authentication failed for $device\n");
        return;
    }

    # Disable paging
    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#', 5);

    # --- CPU Check ---
    $ssh->send("show processes cpu | include CPU");
    my $cpu_out = $ssh->waitfor('\$|#', $timeout) // '';
    my ($cpu_5s, $cpu_1m, $cpu_5m) = ('?', '?', '?');
    if ($cpu_out =~ /CPU\s+utilization[^:]*:\s*(\d+)%\/(\d+)%;\s*one\s+minute:\s*(\d+)%;\s*five\s+minutes:\s*(\d+)%/i) {
        $cpu_5s = $1; $cpu_1m = $3; $cpu_5m = $4;
    } elsif ($cpu_out =~ /(\d+)%\/(\d+)%;.*?(\d+)%;.*?(\d+)%/) {
        $cpu_5s = $1; $cpu_1m = $3; $cpu_5m = $4;
    }
    my $cpu_status = 'OK';
    $cpu_status = 'WARNING'  if $cpu_5m ne '?' && $cpu_5m >= $cpu_warn;
    $cpu_status = 'CRITICAL' if $cpu_5m ne '?' && $cpu_5m >= $cpu_crit;
    log_print("  CPU  : 5s=$cpu_5s% 1m=$cpu_1m% 5m=$cpu_5m% [$cpu_status]\n");

    # --- Memory Check ---
    $ssh->send("show processes memory | include Processor");
    my $mem_out = $ssh->waitfor('\$|#', $timeout) // '';
    my $mem_status = 'OK';
    if ($mem_out =~ /Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)/i) {
        my ($total, $used, $free) = ($1, $2, $3);
        my $pct_free = $total > 0 ? int(($free / $total) * 100) : 0;
        $mem_status = 'WARNING'  if $pct_free <= $mem_warn;
        $mem_status = 'CRITICAL' if $pct_free <= $mem_crit;
        log_print(sprintf("  MEM  : total=%s used=%s free=%s (%.0f%% free) [%s]\n",
            $total, $used, $free, $pct_free, $mem_status));
    } else {
        log_print("  MEM  : [PARSE ERROR - output: " . substr($mem_out, 0, 80) . "]\n");
    }

    # --- Environment (temperature/power/fans) ---
    $ssh->send("show environment all");
    my $env_out = $ssh->waitfor('\$|#', $timeout) // '';
    my @env_issues;
    while ($env_out =~ /^(.+(?:Temperature|Fan|Power|Supply).+(?:CRITICAL|FAIL|NOT OK|SHUTDOWN).*)$/gim) {
        push @env_issues, "  [!!] $1\n";
    }
    if (@env_issues) {
        log_print("  ENV  : [CRITICAL] Environmental alerts:\n");
        log_print($_) for @env_issues;
    } elsif ($env_out =~ /\S/) {
        log_print("  ENV  : All sensors OK\n");
    } else {
        log_print("  ENV  : Not supported or no data returned\n");
    }

    $ssh->close();
}

check_device($_) for @hosts;

my $done_ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
log_print("\n[$done_ts] Health check complete. Checked " . scalar(@hosts) . " device(s).\n");
close $log_fh if $log_fh;