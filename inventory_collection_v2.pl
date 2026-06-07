#!/usr/bin/perl
#
# hw_health_check.pl - Network Device Hardware Health Monitor
#
# PURPOSE:
#   Checks CPU utilization, memory usage, environmental sensors (temperature,
#   fans, power supplies) on Cisco IOS/IOS-XE devices. Flags any readings
#   that exceed warning thresholds. Useful for pre-change health baselines
#   and post-change verification.
#
# USAGE:
#   Single device:   ./hw_health_check.pl -h 192.168.1.1 -u admin -p secret
#   Device file:     ./hw_health_check.pl -f devices.txt -u admin -p secret
#   With log output: ./hw_health_check.pl -h 192.168.1.1 -u admin -p secret -l health.log
#
# DEVICE FILE FORMAT:
#   One IP or hostname per line. Lines starting with # are ignored.
#
# PREREQUISITES:
#   cpan install Net::SSH::Expect
#
# THRESHOLDS:
#   CPU  > 70% (5-min average) = WARNING
#   CPU  > 90% = CRITICAL
#   MEM  > 80% used = WARNING

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $pass, $device_file, $log_file, $help);
GetOptions(
    'h=s' => \$host,
    'u=s' => \$user,
    'p=s' => \$pass,
    'f=s' => \$device_file,
    'l=s' => \$log_file,
    'help' => \$help,
) or die "Error parsing options\n";

if ($help || (!$host && !$device_file) || !$user || !$pass) {
    print "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l <logfile>]\n";
    exit 1;
}

my @devices = $host ? ($host) : ();
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

sub output {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub check_device {
    my $dev = shift;
    my $ts  = strftime("%Y-%m-%d %H:%M:%S", localtime);

    output("\n=== $dev  [$ts] ===\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $dev,
        user        => $user,
        password     => $pass,
        raw_pty     => 1,
        timeout      => 20,
    );

    eval {
        my $login = $ssh->login();
        if ($login !~ /[>#]/) {
            die "Authentication failed or unexpected prompt\n";
        }
    };
    if ($@) {
        output("  [ERROR] Cannot connect to $dev: $@");
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\s*[>#]', 5);

    # CPU check
    $ssh->send("show processes cpu | include CPU utilization\n");
    my $cpu_out = $ssh->waitfor('\s*[>#]', 10) // '';
    if ($cpu_out =~ /five minutes:\s*(\d+)%/) {
        my $cpu5 = $1;
        my $status = $cpu5 >= 90 ? 'CRITICAL' : $cpu5 >= 70 ? 'WARNING' : 'OK';
        output("  CPU (5-min avg): $cpu5%  [$status]\n");
    } else {
        output("  CPU: could not parse output\n");
    }

    # Memory check
    $ssh->send("show processes memory | include Processor\n");
    my $mem_out = $ssh->waitfor('\s*[>#]', 10) // '';
    if ($mem_out =~ /Processor\s+\S+\s+(\d+)\s+(\d+)/) {
        my ($used, $free) = ($1, $2);
        my $total = $used + $free;
        my $pct   = $total > 0 ? int(($used / $total) * 100) : 0;
        my $status = $pct >= 80 ? 'WARNING' : 'OK';
        output(sprintf("  Memory: %dMB used / %dMB total (%d%%)  [%s]\n",
            $used/1024, $total/1024, $pct, $status));
    } else {
        output("  Memory: could not parse output\n");
    }

    # Environmental sensors
    $ssh->send("show env all\n");
    my $env_out = $ssh->waitfor('\s*[>#]', 10) // '';

    my @warnings;
    while ($env_out =~ /^(.+?)\s+(FAULTY|Fan\s+Fail|Critical|FAIL)/gim) {
        push @warnings, $1;
    }
    if (@warnings) {
        output("  ENV: ALERT - " . join(", ", @warnings) . "\n");
    } elsif ($env_out =~ /\S/) {
        my $temp_count = () = $env_out =~ /Normal/gi;
        output("  ENV: $temp_count sensor(s) normal\n");
    } else {
        # IOS-XE fallback
        $ssh->send("show version | include uptime\n");
        my $up_out = $ssh->waitfor('\s*[>#]', 5) // '';
        ($up_out =~ /uptime is (.+)/) and output("  Uptime: $1\n");
    }

    $ssh->close();
}

for my $dev (@devices) {
    check_device($dev);
}

output("\nDone. Checked " . scalar(@devices) . " device(s).\n");
close $log_fh if $log_fh;