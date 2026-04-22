```perl
#!/usr/bin/perl
#
# interface_error_check.pl - Interface Error Rate Monitor for Cisco IOS/IOS-XE
#
# Purpose:
#   Connects to one or more network devices via SSH and parses interface error
#   counters (CRC, input errors, output drops, giants, runts). Flags interfaces
#   whose error counts exceed configurable thresholds. Useful for identifying
#   bad cables, duplex mismatches, or oversubscribed uplinks before they cause
#   outages.
#
# Usage:
#   Single device:   ./interface_error_check.pl -h 192.168.1.1 -u admin -p secret
#   Device list:     ./interface_error_check.pl -f devices.txt -u admin -p secret
#   With log file:   ./interface_error_check.pl -h 192.168.1.1 -u admin -p secret -l errors.log
#   Custom threshold:./interface_error_check.pl -h 192.168.1.1 -u admin -p secret -t 50
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to target devices with 'show interfaces' privilege
#   Devices must present a standard IOS/IOS-XE prompt (hostname#)
#
# Output:
#   PASS  - interface has zero or negligible errors
#   WARN  - error count exceeds warning threshold (default: 10)
#   FAIL  - error count exceeds critical threshold (default: 100)
#
# Author: Network Automation Portfolio
# Version: 1.0

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file, $threshold_warn, $threshold_fail);
$threshold_warn = 10;
$threshold_fail = 100;

GetOptions(
    'h|host=s'      => \$host,
    'f|file=s'      => \$device_file,
    'u|user=s'      => \$username,
    'p|pass=s'      => \$password,
    'l|log=s'       => \$log_file,
    't|threshold=i' => \$threshold_warn,
) or die "Error in arguments. Use -h host or -f file, -u user, -p pass\n";

die "Must specify -u username\n" unless $username;
die "Must specify -p password\n" unless $password;
die "Must specify -h host or -f device file\n" unless $host || $device_file;

$threshold_fail = $threshold_warn * 10;

my @devices;
if ($host) {
    push @devices, $host;
} elsif ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open device file $device_file: $!\n";
    while (<$fh>) {
        chomp;
        s/#.*//;   # strip comments
        s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>', $log_file) or die "Cannot open log file $log_file: $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);

sub output {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub check_device {
    my $device = shift;
    output("=" x 60 . "\n");
    output("Device: $device  |  $timestamp\n");
    output("=" x 60 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $username,
        password     => $password,
        raw_pty     => 1,
        timeout     => 15,
    );

    eval {
        my $login_output = $ssh->login();
        if ($login_output !~ /[>#]/) {
            die "Login failed - unexpected prompt: $login_output\n";
        }
    };
    if ($@) {
        output("  ERROR: Cannot connect to $device: $@\n");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\#\s*$', 5);

    $ssh->send("show interfaces");
    my $output = $ssh->waitfor('\#\s*$', 30);

    unless ($output) {
        output("  ERROR: No response from 'show interfaces' on $device\n");
        $ssh->close();
        return;
    }

    my $current_iface = '';
    my %iface_errors;

    for my $line (split /\n/, $output) {
        if ($line =~ /^(\S+)\s+is\s+(?:up|down|administratively down)/) {
            $current_iface = $1;
            $iface_errors{$current_iface} = { crc => 0, input_errors => 0, output_drops => 0, giants => 0, runts => 0 };
        }
        next unless $current_iface;
        if ($line =~ /(\d+)\s+input errors.*?(\d+)\s+CRC/) {
            $iface_errors{$current_iface}{input_errors} = $1;
            $iface_errors{$current_iface}{crc}          = $2;
        }
        if ($line =~ /(\d+)\s+giants.*?(\d+)\s+runts/) {
            $iface_errors{$current_iface}{giants} = $1;
            $iface_errors{$current_iface}{runts}  = $2;
        }
        if ($line =~ /(\d+)\s+output drops/) {
            $iface_errors{$current_iface}{output_drops} = $1;
        }
    }

    my $issues_found = 0;
    for my $iface (sort keys %iface_errors) {
        my $e      = $iface_errors{$iface};
        my $total  = $e->{input_errors} + $e->{output_drops} + $e->{crc};
        my $status = $total == 0       ? 'PASS'
                   : $total < $threshold_warn ? 'PASS'
                   : $total < $threshold_fail ? 'WARN'
                   :                            'FAIL';

        next if $status eq 'PASS';
        $issues_found++;
        output(sprintf("  [%-4s] %-35s  CRC:%-6d InErr:%-6d OutDrop:%-6d Giants:%-5d Runts:%d\n",
            $status, $iface,
            $e->{crc}, $e->{input_errors}, $e->{output_drops},
            $e->{giants}, $e->{runts}));
    }

    output("  All interfaces within thresholds (warn=$threshold_warn fail=$threshold_fail)\n") unless $issues_found;
    output("  Total interfaces checked: " . scalar(keys %iface_errors) . "\n");
    $ssh->send("exit");
    $ssh->close();
}

for my $dev (@devices) {
    check_device($dev);
}

output("\nScan complete: " . scalar(@devices) . " device(s) checked\n");
close $log_fh if $log_fh;
```