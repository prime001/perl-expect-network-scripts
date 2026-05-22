#!/usr/bin/perl
#
# device_health.pl - Network Device Health Monitor
#
# Purpose:
#   Collects CPU utilization, memory usage, and environmental status
#   (temperature, fans, power supplies) from Cisco IOS/IOS-XE devices.
#   Useful for capacity planning, proactive monitoring, and pre-change checks.
#
# Usage:
#   Single device:  perl device_health.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    perl device_health.pl -f devices.txt -u admin -p secret
#   With logging:   perl device_health.pl -h 192.168.1.1 -u admin -p secret -l health.log
#   Custom timeout: perl device_health.pl -h 192.168.1.1 -u admin -p secret -t 45
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   cpan Getopt::Long
#
# Device file format (one IP or hostname per line; blank lines and # comments ignored):
#   192.168.1.1
#   core-router-01
#   # standby unit
#   192.168.1.2
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $pass, $device_file, $log_file);
my $timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'f|file=s'    => \$device_file,
    'l|log=s'     => \$log_file,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l <log>] [-t <secs>]\n";

die "ERROR: Specify -h <host> or -f <file>\n"  unless $host || $device_file;
die "ERROR: -u <username> is required\n"        unless $user;
die "ERROR: -p <password> is required\n"        unless $pass;

my @devices;
if ($host) {
    @devices = ($host);
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^\s*#/;
        push @devices, $_;
    }
    close $fh;
    die "ERROR: No devices found in $device_file\n" unless @devices;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

sub emit {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub check_device {
    my ($device) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);

    emit("\n" . "=" x 60 . "\n");
    emit("Host: $device    Checked: $ts\n");
    emit("=" x 60 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $user,
        password => $pass,
        raw_pty  => 1,
        timeout  => $timeout,
    );

    eval {
        my $login = $ssh->login();
        die "Unexpected prompt — check credentials or enable password\n"
            unless $login =~ /[>#]/;
    };
    if ($@) {
        emit("CONNECT ERROR [$device]: $@\n");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\s*[>#]', $timeout) or warn "Pager disable timed out on $device\n";

    my %commands = (
        'CPU Utilization'     => 'show processes cpu | include CPU utilization',
        'Memory Utilization'  => 'show processes memory | include Processor',
        'Device Uptime'       => 'show version | include uptime',
        'Environmental Status'=> 'show environment all',
    );

    for my $section ('CPU Utilization', 'Memory Utilization', 'Device Uptime', 'Environmental Status') {
        my $cmd = $commands{$section};
        emit("\n--- $section ---\n");

        $ssh->send($cmd);
        my $output = $ssh->waitfor('\s*[>#]', $timeout);

        unless (defined $output && $output =~ /\S/) {
            emit("  [no output or timeout]\n");
            next;
        }

        # Strip echoed command and trailing prompt
        $output =~ s/^\Q$cmd\E\r?\n//;
        $output =~ s/\s*[>#]\s*$//;

        for my $line (split /\r?\n/, $output) {
            next unless $line =~ /\S/;
            emit("  $line\n");
        }
    }

    $ssh->close();
    emit("\nDone: $device\n");
}

for my $device (@devices) {
    eval { check_device($device) };
    emit("FATAL [$device]: $@\n") if $@;
}

my $finish = strftime('%Y-%m-%d %H:%M:%S', localtime);
emit("\nHealth check complete: $finish\n");
close $log_fh if $log_fh;