Now I have a clear picture of what's covered. Writing a CPU/memory health monitor — distinct from all existing scripts and highly practical for day-to-day network ops.

#!/usr/bin/perl
#
# health_monitor.pl - Device CPU, Memory, and Environmental Health Check
#
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE devices via SSH and collects
#   CPU utilization, processor memory stats, and environmental sensor status
#   (fans, power supplies, temperature). Useful for capacity planning, proactive
#   alerting before resource exhaustion causes outages, and post-maintenance
#   health validation.
#
# Usage:
#   Single device:  ./health_monitor.pl -h 10.0.0.1 -u admin -p secret
#   Device list:    ./health_monitor.pl -f devices.txt -u admin -p secret
#   With log file:  ./health_monitor.pl -f devices.txt -u admin -p secret -l health.log
#   Custom timeout: ./health_monitor.pl -h 10.0.0.1 -u admin -p secret -t 45
#
# Device file format: one IP or hostname per line; lines starting with # are ignored
#
# Prerequisites:
#   Perl modules: Net::SSH::Expect, Getopt::Long
#   Install:      cpanm Net::SSH::Expect
#   Devices must have SSH enabled and sufficient privilege to run 'show' commands
#
# Supported platforms: Cisco IOS, IOS-XE (NX-OS uses different env command syntax)

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case bundling);
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file);
my $timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$device_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'l|log=s'     => \$log_file,
    't|timeout=i' => \$timeout,
) or usage();

$username //= $ENV{NET_USER} // 'admin';
$password //= $ENV{NET_PASS} or die "Password required: use -p or set NET_PASS env var\n";

my @devices;
if ($host) {
    push @devices, $host;
} elsif ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^#/;
        push @devices, $_;
    }
    close $fh;
} else {
    usage();
}

die "No devices to process\n" unless @devices;

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
my ($ok_count, $warn_count, $err_count) = (0, 0, 0);

for my $device (@devices) {
    emit($log_fh, "\n" . "=" x 60);
    emit($log_fh, "Device: $device  |  $timestamp");
    emit($log_fh, "=" x 60);

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $device,
            user     => $username,
            password => $password,
            raw_pty  => 1,
            timeout  => $timeout,
        );
    };
    if ($@ || !$ssh) {
        emit($log_fh, "  ERROR: SSH session failed - $@");
        $err_count++;
        next;
    }

    my $logged_in = eval { $ssh->login() };
    if ($@ || !$logged_in) {
        emit($log_fh, "  ERROR: Authentication failed - $@");
        $err_count++;
        next;
    }

    $ssh->exec("terminal length 0");

    my $device_ok = 1;

    # --- CPU Utilization ---
    emit($log_fh, "\n[CPU Utilization]");
    my $cpu = $ssh->exec("show processes cpu | include CPU utilization");
    if ($cpu && $cpu =~ /five seconds: (\d+)%[^;]*;\s*one minute: (\d+)%;\s*five minutes: (\d+)%/) {
        my ($sec5, $min1, $min5) = ($1, $2, $3);
        emit($log_fh, "  5-second : $sec5%");
        emit($log_fh, "  1-minute : $min1%");
        emit($log_fh, "  5-minute : $min5%");
        if ($min5 >= 80) {
            emit($log_fh, "  *** WARN: 5-min CPU at $min5% (threshold 80%) ***");
            $device_ok = 0;
        }
    } else {
        emit($log_fh, "  Could not parse CPU output");
    }

    # --- Memory Utilization ---
    emit($log_fh, "\n[Memory Utilization]");
    my $mem = $ssh->exec("show processes memory | include Processor");
    if ($mem && $mem =~ /Total:\s+(\d+)\s+Used:\s+(\d+)\s+Free:\s+(\d+)/) {
        my ($total, $used, $free) = ($1, $2, $3);
        my $pct = int($used / $total * 100);
        emit($log_fh, sprintf("  Total: %d MB  Used: %d MB  Free: %d MB  (%d%% used)",
            $total/1048576, $used/1048576, $free/1048576, $pct));
        if ($pct >= 85) {
            emit($log_fh, "  *** WARN: Memory at $pct% (threshold 85%) ***");
            $device_ok = 0;
        }
    } else {
        emit($log_fh, "  Could not parse memory output");
    }

    # --- Environmental Status ---
    emit($log_fh, "\n[Environmental Status]");
    my $env = $ssh->exec("show environment all");
    if ($env && $env !~ /Invalid input|% Unknown/) {
        my @crits  = grep { /CRITICAL|FAIL/i    } split /\n/, $env;
        my @warns  = grep { /WARNING|WARN(?!ING)/i } split /\n/, $env;
        if (@crits) {
            emit($log_fh, "  *** CRITICAL: " . scalar(@crits) . " sensor(s) in critical state ***");
            emit($log_fh, "  $_") for @crits;
            $device_ok = 0;
        } elsif (@warns) {
            emit($log_fh, "  WARN: " . scalar(@warns) . " sensor warning(s)");
            emit($log_fh, "  $_") for @warns;
            $device_ok = 0;
        } else {
            emit($log_fh, "  All sensors: OK");
        }
    } else {
        # Platforms without 'show environment' (e.g. older 2900-series)
        emit($log_fh, "  show environment not supported on this platform");
    }

    $ssh->close();

    if ($device_ok) { $ok_count++ } else { $warn_count++ }
}

emit($log_fh, "\n" . "-" x 60);
emit($log_fh, "Summary: $ok_count OK  $warn_count WARNING  $err_count ERROR");
emit($log_fh, "-" x 60);

close $log_fh if $log_fh;
print "\nLog appended to: $log_file\n" if $log_file;

sub emit {
    my ($fh, $msg) = @_;
    print "$msg\n";
    print $fh "$msg\n" if $fh;
}

sub usage {
    die <<END;
Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile] [-t timeout_sec]

  -h  Target device hostname or IP
  -f  File with one device per line (# lines ignored)
  -u  SSH username (default: \$NET_USER or 'admin')
  -p  SSH password (default: \$NET_PASS)
  -l  Append results to this log file
  -t  Per-device SSH timeout in seconds (default: 30)

Thresholds: CPU 5-min >= 80%  |  Memory >= 85%  |  Any CRITICAL/WARNING env sensor
END
}