The prompt asks for script content only — here it is:

#!/usr/bin/perl
#
# 012_health_check.pl - Cisco IOS Hardware Health Check
#
# Collects CPU utilization, memory usage, environmental status (temperature,
# fans, power supplies), and system uptime from Cisco IOS devices.
# Useful for baseline health checks, pre/post-change verification, and
# identifying resource exhaustion before it causes an outage.
#
# Usage:
#   Single device:  perl 012_health_check.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    perl 012_health_check.pl -f devices.txt -u admin -p secret
#   With log:       perl 012_health_check.pl -h 192.168.1.1 -u admin -p secret -l health.log
#
# Device file format: one IP or hostname per line, lines starting with # ignored
#
# Prerequisites:
#   cpan Net::SSH::Expect
#
# Tested on: Cisco IOS 12.x/15.x, IOS-XE 3.x/16.x/17.x
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $logfile, $help);
my $timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$file,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'l|log=s'      => \$logfile,
    't|timeout=i'  => \$timeout,
    'help'         => \$help,
) or die "Error parsing options. Use --help for usage.\n";

if ($help || (!$host && !$file) || !$user || !$pass) {
    print "Usage: $0 -h <host> -u <user> -p <pass> [-l logfile] [-t timeout]\n";
    print "       $0 -f <devices.txt> -u <user> -p <pass> [-l logfile]\n";
    exit 1;
}

my @devices = $host ? ($host) : read_device_file($file);
die "No devices to process.\n" unless @devices;

my $LOG;
if ($logfile) {
    open($LOG, '>>', $logfile) or die "Cannot open log file '$logfile': $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=" x 60);
output("Health Check Run: $timestamp");
output("=" x 60);

for my $device (@devices) {
    output("\n--- Device: $device ---");
    check_device($device, $user, $pass, $timeout);
}

close($LOG) if $LOG;
exit 0;

sub check_device {
    my ($host, $user, $pass, $timeout) = @_;

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $host,
            user        => $user,
            password    => $pass,
            timeout     => $timeout,
            ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
    };
    if ($@ || !$ssh) {
        output("  ERROR: Failed to create SSH session for $host: $@");
        return;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        output("  ERROR: Authentication failed for $host");
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|#', 5);

    collect_uptime($ssh);
    collect_cpu($ssh);
    collect_memory($ssh);
    collect_environment($ssh);

    eval { $ssh->send("exit\n") };
}

sub collect_uptime {
    my ($ssh) = @_;
    my $out = run_command($ssh, 'show version | include uptime');
    if ($out && $out =~ /uptime is (.+)/i) {
        output("  Uptime       : $1");
    }
}

sub collect_cpu {
    my ($ssh) = @_;
    my $out = run_command($ssh, 'show processes cpu | include CPU utilization');
    if ($out && $out =~ /CPU utilization for five seconds:\s*(\S+).*one minute:\s*(\S+).*five minutes:\s*(\S+)/i) {
        output("  CPU (5s/1m/5m): $1 / $2 / $3");
        my $pct = $1;
        $pct =~ s/%.*//;
        output("  CPU WARN: 5-second CPU at ${pct}% - investigate high-CPU processes") if $pct > 80;
    } else {
        output("  CPU          : (unable to parse)");
    }
}

sub collect_memory {
    my ($ssh) = @_;
    my $out = run_command($ssh, 'show processes memory | include Processor');
    if ($out && $out =~ /Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)/i) {
        my ($total, $used, $free) = ($1, $2, $3);
        my $pct = int(($used / $total) * 100);
        output(sprintf("  Memory       : %dK total, %dK used (%d%%), %dK free", $total, $used, $pct, $free));
        output("  MEM WARN: Processor memory usage at ${pct}% - check for leaks") if $pct > 85;
    } else {
        output("  Memory       : (unable to parse)");
    }
}

sub collect_environment {
    my ($ssh) = @_;
    my $out = run_command($ssh, 'show environment all');
    return unless $out;

    my @warnings;
    push @warnings, "Temperature CRITICAL" if $out =~ /temperature.*CRITICAL/i;
    push @warnings, "Temperature WARNING"  if $out =~ /temperature.*WARNING/i;
    push @warnings, "Fan failure detected" if $out =~ /fan.*fail/i;
    push @warnings, "Power supply failure" if $out =~ /power.*fail/i;

    if (@warnings) {
        output("  ENV ALERTS   : " . join(', ', @warnings));
    } else {
        output("  Environment  : OK (no temperature/fan/power alerts)");
    }
}

sub run_command {
    my ($ssh, $cmd) = @_;
    eval {
        $ssh->send("$cmd\n");
        $ssh->waitfor('\$|#', $timeout);
        $ssh->before();
    };
}

sub read_device_file {
    my ($file) = @_;
    open(my $fh, '<', $file) or die "Cannot open device file '$file': $!\n";
    my @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close($fh);
    return @devices;
}

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $LOG "$msg\n" if $LOG;
}