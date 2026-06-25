#!/usr/bin/perl
=head1 NAME
device_connectivity_test.pl - Batch SSH connectivity and system health checker

=head1 SYNOPSIS
device_connectivity_test.pl <device_ip> [--log <logfile>]
device_connectivity_test.pl --file <device_list> [--log <logfile>] [--user <username>]

=head1 DESCRIPTION
Performs quick SSH connectivity tests and gathers basic system health metrics
from network devices. Reports uptime, software version, and reachability status.
Outputs results to STDOUT and optional log file for infrastructure monitoring.

=head1 PREREQUISITES
Net::SSH::Expect, SSH access to devices, valid credentials via environment
variables NET_USER and NET_PASS or ~/.ssh config

=head1 EXAMPLES
device_connectivity_test.pl 10.1.1.1
device_connectivity_test.pl --file devices.txt --log connectivity.log --user netadmin

=cut

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use Time::HiRes qw(time);

my ($target_device, $device_file, $logfile, $username, $timeout);
GetOptions(
    'device|d=s'  => \$target_device,
    'file|f=s'    => \$device_file,
    'log|l=s'     => \$logfile,
    'user|u=s'    => \$username,
    'timeout|t=i' => \$timeout,
) or die "Error in command line arguments\n";

$timeout ||= 20;
$username ||= $ENV{NET_USER} || 'admin';
my $password = $ENV{NET_PASS} || '';

die "Specify --device or --file argument\n" unless ($target_device || $device_file);

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log file $logfile: $!\n";
    select($log_fh);
    $| = 1;
    select(STDOUT);
    print_log("=== Connectivity Check Started at " . scalar(localtime) . " ===\n");
}

sub print_log {
    my ($msg) = @_;
    print STDOUT $msg;
    print $log_fh $msg if $log_fh;
}

sub test_device {
    my ($device_ip) = @_;
    my $start_time = time();
    my $ssh;
    
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $device_ip,
            user     => $username,
            password => $password,
            timeout  => $timeout,
            raw_pty  => 1,
        );
        
        $ssh->login() or die "SSH login failed";
    };
    
    if ($@) {
        my $elapsed = sprintf("%.2f", time() - $start_time);
        print_log("[FAIL] $device_ip - Connection error after ${elapsed}s: $@\n");
        return 0;
    }
    
    my $uptime = "unknown";
    my $version = "unknown";
    
    eval {
        $ssh->send("show version");
        $ssh->waitfor('.*[#>]', $timeout) or die "Command timeout";
        my $output = $ssh->before();
        
        if ($output =~ /uptime is\s+(.+?)[\r\n]/i) {
            $uptime = $1;
        }
        if ($output =~ /(?:IOS|Version|Software)\s+(?:XE\s+)?(\d+\.\d+[\.\d\w]+)/i) {
            $version = $1;
        }
    };
    
    eval {
        $ssh->close();
    };
    
    my $elapsed = sprintf("%.2f", time() - $start_time);
    print_log("[OK  ] $device_ip - Uptime: $uptime | Version: $version (${elapsed}s)\n");
    return 1;
}

my $success_count = 0;
my $fail_count = 0;

if ($target_device) {
    test_device($target_device) ? $success_count++ : $fail_count++;
} elsif ($device_file) {
    unless (-f $device_file) {
        die "Device file not found: $device_file\n";
    }
    
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (my $line = <$fh>) {
        chomp($line);
        next if $line =~ /^\s*#/ || $line =~ /^\s*$/;
        $line =~ s/^\s+|\s+$//g;
        test_device($line) ? $success_count++ : $fail_count++;
    }
    close($fh);
}

print_log("\n=== Summary: $success_count passed, $fail_count failed ===\n");
close($log_fh) if $log_fh;

exit($fail_count > 0 ? 1 : 0);