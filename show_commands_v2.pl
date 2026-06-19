#!/usr/bin/perl
# =============================================================================
# health_check.pl - Network Device CPU/Memory/Environment Health Monitor
# =============================================================================
# PURPOSE:
#   Polls Cisco IOS/IOS-XE devices for CPU utilization, memory usage, and
#   environmental status (temperature, fans, power supplies). Flags values
#   that exceed warning thresholds. Useful for capacity planning, incident
#   triage, and routine operational health audits.
#
# USAGE:
#   health_check.pl <host> [--user USER] [--pass PASS] [--log FILE]
#   health_check.pl --file <device_list.txt> [--log FILE]
#
# PREREQUISITES:
#   cpan Net::SSH::Expect Getopt::Long
#   SSH enabled on target device; credentials via args or env vars
#   NET_USER / NET_PASS environment variables used as fallback
#
# THRESHOLDS:
#   CPU 1-minute > 80%  => WARN
#   Memory used  > 85%  => WARN
#   Any env FAIL/CRITICAL line => ALERT
#
# TESTED AGAINST:
#   Cisco IOS 15.x, IOS-XE 16.x/17.x
#
# EXAMPLES:
#   health_check.pl 192.168.1.1 --user admin --pass s3cr3t
#   health_check.pl --file routers.txt --log /var/log/health.log
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config pass_through);
use POSIX qw(strftime);

my ($device_file, $log_file, $help);
my $username = $ENV{NET_USER} // 'admin';
my $password = $ENV{NET_PASS} // '';
my $timeout  = 30;

GetOptions(
    'file=s' => \$device_file,
    'log=s'  => \$log_file,
    'user=s' => \$username,
    'pass=s' => \$password,
    'help'   => \$help,
) or die "Invalid options. Run with --help for usage.\n";

if ($help) {
    print "Usage: $0 <host> [--user USER] [--pass PASS] [--log FILE]\n";
    print "       $0 --file device_list.txt [--log FILE]\n";
    exit 0;
}

my @devices;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open '$device_file': $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
    die "No hosts found in '$device_file'\n" unless @devices;
} elsif (@ARGV) {
    @devices = ($ARGV[0]);
} else {
    die "No host specified. Use: $0 <host> or $0 --file <list>\n";
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log '$log_file': $!\n";
}

sub emit {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub check_device {
    my $host = shift;
    my $ts   = strftime('%Y-%m-%d %H:%M:%S', localtime);
    emit("\n[$ts] === $host ===\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $username,
        password    => $password,
        raw_pty     => 1,
        timeout     => $timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    eval {
        my $login = $ssh->login();
        die "Auth failed or unexpected banner on $host\n"
            unless defined $login && $login =~ /[>#]/;
    };
    if ($@) {
        emit("  [ERROR] $@");
        return;
    }

    $ssh->exec("terminal length 0");

    # --- CPU ---
    my $cpu = $ssh->exec("show processes cpu | include CPU utilization");
    if ($cpu && $cpu =~ /CPU utilization[^:]*:\s*(\d+)%.*?(\d+)%.*?(\d+)%/) {
        my ($s5, $m1, $m5) = ($1, $2, $3);
        my $warn = $m1 > 80 ? '  <<WARN: HIGH CPU>>' : '';
        emit(sprintf("  CPU   : 5s=%-3s%%  1m=%-3s%%  5m=%-3s%%%s\n",
            $s5, $m1, $m5, $warn));
    } else {
        emit("  CPU   : [parse error -- output: " . ($cpu // 'none') . "]\n");
    }

    # --- Memory ---
    my $mem = $ssh->exec("show processes memory | include Processor Pool Total");
    if ($mem && $mem =~ /Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*(\d+)/) {
        my ($tot, $used, $free) = ($1, $2, $3);
        my $pct  = $tot > 0 ? int($used / $tot * 100) : 0;
        my $warn = $pct > 85 ? '  <<WARN: LOW MEMORY>>' : '';
        emit(sprintf("  MEM   : used=%dMB  free=%dMB  (%d%% utilized)%s\n",
            $used/1024/1024, $free/1024/1024, $pct, $warn));
    } else {
        emit("  MEM   : [parse error]\n");
    }

    # --- Environment ---
    my $env = $ssh->exec("show environment all 2>/dev/null");
    if ($env && length($env) > 20) {
        my @alerts;
        push @alerts, 'TEMP-CRITICAL' if $env =~ /temperature.*critical/i;
        push @alerts, 'TEMP-WARNING'  if $env =~ /temperature.*warning/i;
        push @alerts, 'FAN-FAILURE'   if $env =~ /fan\s+\S+.*(?:fail|shutdown)/i;
        push @alerts, 'PSU-FAILURE'   if $env =~ /power.*(?:fail|absent|down)/i;
        if (@alerts) {
            emit("  ENV   : [ALERT] " . join(', ', @alerts) . "\n");
        } else {
            emit("  ENV   : OK\n");
        }
    } else {
        emit("  ENV   : [not supported on this platform]\n");
    }

    # --- Uptime (bonus context) ---
    my $ver = $ssh->exec("show version | include uptime");
    if ($ver && $ver =~ /^(.+uptime.+?)[\r\n]/m) {
        (my $uptime = $1) =~ s/^\s+//;
        emit("  UPTIME: $uptime\n");
    }

    eval { $ssh->close() };
}

emit("Network Health Check | " . strftime('%Y-%m-%d %H:%M:%S', localtime) . "\n");
emit("Devices: " . scalar(@devices) . "\n");

for my $host (@devices) {
    check_device($host);
}

emit("\nComplete. " . scalar(@devices) . " device(s) polled.\n");
close($log_fh) if $log_fh;