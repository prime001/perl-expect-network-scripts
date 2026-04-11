```perl
#!/usr/bin/perl
# =============================================================================
# cpu_mem_health.pl - Network Device CPU & Memory Health Collector
# =============================================================================
# Purpose:
#   Polls CPU utilization and memory usage from Cisco IOS/IOS-XE devices
#   via SSH. Useful for capacity planning, incident triage, and scheduled
#   health checks across a fleet of network devices.
#
# Usage:
#   Single device:   ./cpu_mem_health.pl -h 192.168.1.1
#   Device list:     ./cpu_mem_health.pl -f devices.txt
#   With logging:    ./cpu_mem_health.pl -f devices.txt -l health.log
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH key auth or plaintext credentials via environment variables:
#     NET_USER, NET_PASS, NET_ENABLE (optional)
#
# Device file format: one IP or hostname per line, # for comments
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $device_file, $log_file);
GetOptions(
    'h=s' => \$host_arg,
    'f=s' => \$device_file,
    'l=s' => \$log_file,
) or die "Usage: $0 [-h host] [-f device_file] [-l log_file]\n";

die "Specify -h HOST or -f FILE\n" unless $host_arg || $device_file;

my $username = $ENV{NET_USER} or die "Set NET_USER environment variable\n";
my $password = $ENV{NET_PASS} or die "Set NET_PASS environment variable\n";
my $enable   = $ENV{NET_ENABLE} || $password;
my $timeout  = 15;

my @devices;
if ($host_arg) {
    push @devices, $host_arg;
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub log_output {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
log_output("=" x 70 . "\n");
log_output("CPU/Memory Health Check  |  $ts\n");
log_output("=" x 70 . "\n\n");

for my $device (@devices) {
    log_output("Device: $device\n");
    log_output("-" x 50 . "\n");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host        => $device,
            user        => $username,
            password    => $password,
            raw_pty     => 1,
            timeout     => $timeout,
        );
        $ssh->login();
    };
    if ($@) {
        log_output("  ERROR: Connection failed - $@\n\n");
        next;
    }

    eval {
        $ssh->send("terminal length 0");
        $ssh->waitfor('\$\s*$|#\s*$', $timeout);

        if ($ssh->waitfor('>\s*$', 1)) {
            $ssh->send("enable");
            $ssh->waitfor('[Pp]assword', $timeout);
            $ssh->send($enable);
            $ssh->waitfor('#\s*$', $timeout);
        }

        # CPU utilization
        $ssh->send("show processes cpu | include CPU utilization");
        my $cpu_out = $ssh->waitfor('#\s*$', $timeout);
        if ($cpu_out =~ /CPU utilization[^:]*:\s*(\d+%[^,]*,\s*\d+%[^,]*,\s*\d+%\s+average)/i) {
            log_output("  CPU  : $1\n");
        } elsif ($cpu_out =~ /(CPU utilization.+)/i) {
            log_output("  CPU  : $1\n");
        } else {
            log_output("  CPU  : (parse failed)\n");
        }

        # Memory
        $ssh->send("show processes memory | include Processor");
        my $mem_out = $ssh->waitfor('#\s*$', $timeout);
        if ($mem_out =~ /Processor\s+(\S+)\s+(\S+)\s+(\S+)/i) {
            my ($total, $used, $free) = ($1, $2, $3);
            my $pct = ($total > 0) ? int(($used / $total) * 100) : 0;
            log_output(sprintf("  MEM  : total=%-10s used=%-10s free=%-10s (%d%% used)\n",
                $total, $used, $free, $pct));
        } else {
            log_output("  MEM  : (parse failed)\n");
        }

        # Environment status (power/fans/temp) - best-effort
        $ssh->send("show environment all | include FAIL|Critical|Warning|OK");
        my $env_out = $ssh->waitfor('#\s*$', $timeout);
        my @env_issues = grep { /FAIL|Critical|Warning/i } split(/\n/, $env_out);
        if (@env_issues) {
            log_output("  ENV  : ALERTS: " . join("; ", map { s/^\s+|\s+$//gr } @env_issues) . "\n");
        } else {
            log_output("  ENV  : OK\n");
        }

        $ssh->send("exit");
    };
    if ($@) {
        log_output("  ERROR: Session error - $@\n");
    }

    log_output("\n");
}

log_output("Collection complete.\n");
close $log_fh if $log_fh;
```