#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# hardware_health.pl - Cisco IOS/IOS-XE Hardware Health Check
#
# PURPOSE:
#   Polls CPU utilization, memory usage, environment (temperature, power
#   supplies, fans) from one or more Cisco routers/switches via SSH.
#   Flags components that exceed warning thresholds so NOC staff can triage
#   before a device goes critical.
#
# USAGE:
#   Single device:   ./hardware_health.pl -H 192.168.1.1 -u admin -p secret
#   Device file:     ./hardware_health.pl -f devices.txt -u admin -p secret
#   With log output: ./hardware_health.pl -H 192.168.1.1 -u admin -p secret -l /var/log/health.log
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   SSH key-based or password auth to target devices
#   'show processes cpu' and 'show environment' available on target platform
#
# THRESHOLDS (edit below):
#   CPU 5-min average  > 70%  => WARNING
#   Free memory        < 20%  => WARNING
# =============================================================================

my ($host_arg, $device_file, $username, $password, $logfile, $timeout);
$timeout = 30;

GetOptions(
    'H|host=s'     => \$host_arg,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$logfile,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -H <host> | -f <file> -u <user> -p <pass> [-l <logfile>] [-t <timeout>]\n";

die "Specify -H <host> or -f <file>\n" unless $host_arg || $device_file;
die "Username required (-u)\n" unless $username;
die "Password required (-p)\n" unless $password;

my @devices;
if ($host_arg) {
    push @devices, $host_arg;
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^#/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!\n";
}

sub output {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub check_device {
    my $host = shift;
    my $ts   = strftime('%Y-%m-%d %H:%M:%S', localtime);
    output("\n=== $host  [$ts] ===\n");

    my $ssh = Net::SSH::Expect->new(
        host               => $host,
        user               => $username,
        password           => $password,
        raw_pty            => 1,
        timeout            => $timeout,
        ssh_option         => '-o StrictHostKeyChecking=no -o ConnectTimeout=15',
    );

    eval { $ssh->run_ssh() or die "SSH failed\n" };
    if ($@) {
        output("  ERROR: Cannot connect to $host: $@\n");
        return;
    }

    eval {
        $ssh->waitfor('[$#>]\s*$', 10) or die "No prompt after login\n";
        $ssh->send('terminal length 0');
        $ssh->waitfor('[$#>]\s*$', 5);
    };
    if ($@) {
        output("  ERROR: Auth/prompt failure on $host: $@\n");
        $ssh->close();
        return;
    }

    # --- CPU ---
    $ssh->send('show processes cpu | include CPU');
    my $cpu_out = $ssh->waitfor('[$#>]\s*$', 15) // '';
    if ($cpu_out =~ /five minutes:\s+(\d+)%/) {
        my $cpu5 = $1;
        my $flag = $cpu5 > 70 ? ' ** WARNING **' : '';
        output("  CPU 5-min avg : ${cpu5}%${flag}\n");
    } else {
        output("  CPU           : unable to parse\n");
    }

    # --- Memory ---
    $ssh->send('show processes memory | include Processor');
    my $mem_out = $ssh->waitfor('[$#>]\s*$', 15) // '';
    if ($mem_out =~ /Processor\s+\S+\s+(\d+)\s+(\d+)/) {
        my ($used, $free) = ($1, $2);
        my $total = $used + $free;
        my $pct_free = $total ? int(($free / $total) * 100) : 0;
        my $flag = $pct_free < 20 ? ' ** WARNING **' : '';
        output(sprintf("  Memory        : used=%s free=%s (%.0f%% free)%s\n",
            _fmt($used), _fmt($free), $pct_free, $flag));
    } else {
        output("  Memory        : unable to parse\n");
    }

    # --- Environment (temp, PSU, fans) ---
    $ssh->send('show environment all');
    my $env_out = $ssh->waitfor('[$#>]\s*$', 20) // '';
    my @env_issues;
    while ($env_out =~ /^(.+(?:Temperature|Power Supply|Fan).+(?:CRITICAL|FAILED|Warning|NOT OK).*)$/gim) {
        push @env_issues, "  !! $1";
    }
    if (@env_issues) {
        output("  Environment   : ALERTS FOUND\n");
        output("$_\n") for @env_issues;
    } elsif ($env_out =~ /\S/) {
        output("  Environment   : OK\n");
    } else {
        output("  Environment   : no data (platform may not support)\n");
    }

    $ssh->send('exit');
    $ssh->close();
}

sub _fmt {
    my $n = shift;
    return sprintf('%.1fMB', $n / 1_048_576) if $n >= 1_048_576;
    return sprintf('%.1fKB', $n / 1_024)     if $n >= 1_024;
    return "${n}B";
}

check_device($_) for @devices;
output("\nDone. " . scalar(@devices) . " device(s) checked.\n");
close $log_fh if $log_fh;