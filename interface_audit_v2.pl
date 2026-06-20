```perl
#!/usr/bin/perl
#
# Device Health Monitor - Uptime, CPU, and Memory Tracker
#
# Purpose:
#   Collects system health metrics (uptime, CPU utilization, memory usage)
#   from network devices via SSH. Useful for capacity planning, trend analysis,
#   and device health monitoring.
#
# Usage:
#   ./device_health_monitor.pl 192.168.1.1
#   ./device_health_monitor.pl --file device_list.txt --log health.log
#   ./device_health_monitor.pl router1 router2 router3 --log metrics.log
#
# Device List Format:
#   One hostname or IP address per line (blank lines and comments with # ignored)
#
# Prerequisites:
#   - Net::SSH::Expect module (cpan install Net::SSH::Expect)
#   - SSH key-based authentication pre-configured
#   - Read permissions on device configurations
#
# Output Format:
#   Timestamp, device, uptime, CPU usage, available memory, connection status
#
# Author: Network Operations Team
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use File::Spec;
use Time::HiRes qw(time);

my ($device_file, $logfile, $username, $timeout) = ('', '', 'admin', 15);
my $help = 0;

GetOptions(
    'file=s'   => \$device_file,
    'log=s'    => \$logfile,
    'user=s'   => \$username,
    'timeout=i' => \$timeout,
    'help'     => \$help,
) or die "Error in command line arguments\n";

if ($help || (!@ARGV && !$device_file)) {
    print "Usage: $0 [hostname|ip] ... [options]\n";
    print "   or: $0 --file devices.txt [--log output.log] [--user admin] [--timeout 15]\n";
    exit 0;
}

my @devices = @ARGV;
push @devices, read_device_file($device_file) if $device_file;

die "No devices specified\n" unless @devices;

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log file '$logfile': $!\n";
    print $log_fh "\n" . ('=' x 80) . "\n";
    print $log_fh "Health Check - " . scalar(localtime) . "\n";
    print $log_fh ('=' x 80) . "\n";
}

foreach my $device (@devices) {
    check_device_health($device);
}

close $log_fh if $log_fh;

sub check_device_health {
    my ($device) = @_;
    my $start_time = time();
    my $timestamp = scalar localtime;
    
    my $output = "\n[$timestamp] Device: $device\n";
    $output .= "-" x 70 . "\n";
    
    eval {
        my $ssh = Net::SSH::Expect->new(
            host => $device,
            user => $username,
            raw_pty => 1,
            timeout => $timeout,
        );
        
        $ssh->login() or die "SSH login failed for $device\n";
        
        # Try Cisco commands first
        my $uptime_data = fetch_uptime($ssh, $device);
        my $cpu_data = fetch_cpu_usage($ssh);
        my $memory_data = fetch_memory($ssh);
        
        $output .= "Status: Connected\n";
        $output .= $uptime_data;
        $output .= $cpu_data;
        $output .= $memory_data;
        
        $ssh->close();
    };
    
    if ($@) {
        my $error = $@;
        $error =~ s/\n/ /g;
        $output .= "Status: FAILED\n";
        $output .= "Error: $error\n";
    }
    
    my $elapsed = sprintf("%.2f", time() - $start_time);
    $output .= "Query Time: ${elapsed}s\n";
    
    print $output;
    print $log_fh $output if $log_fh;
}

sub fetch_uptime {
    my ($ssh, $device) = @_;
    
    my $result = "Uptime: ";
    
    eval {
        # Cisco IOS/XE
        my $data = $ssh->exec("show version | include uptime");
        if ($data && $data !~ /^\s*$/) {
            $data =~ s/^.*uptime\s+is\s+//i;
            $data =~ s/\s*$//;
            return "Uptime: $data\n";
        }
        
        # Juniper
        $data = $ssh->exec("show system uptime");
        if ($data && $data !~ /^\s*$/) {
            my @lines = split /\n/, $data;
            return "Uptime: " . $lines[0] . "\n";
        }
    };
    
    return "Uptime: Unable to retrieve\n";
}

sub fetch_cpu_usage {
    my ($ssh) = @_;
    
    my $result = "CPU Usage: ";
    
    eval {
        # Cisco IOS/XE
        my $data = $ssh->exec("show processes cpu | include CPU");
        if ($data && $data =~ /(\d+\%)/) {
            return "CPU Usage: $1\n";
        }
        
        # Juniper
        $data = $ssh->exec("show system processes");
        if ($data && $data =~ /CPU\s+(\d+)/) {
            return "CPU Usage: $1%\n";
        }
    };
    
    return "CPU Usage: Unable to retrieve\n";
}

sub fetch_memory {
    my ($ssh) = @_;
    
    my $result = "Memory: ";
    
    eval {
        # Cisco IOS/XE
        my $data = $ssh->exec("show memory | include Processor");
        if ($data) {
            my @parts = split /\s+/, $data;
            if (@parts >= 5) {
                my $used = $parts[2];
                my $total = $parts[4];
                my $pct = int(($used / $total) * 100);
                return "Memory: $pct% used ($used/$total bytes)\n";
            }
        }
        
        # Juniper
        $data = $ssh->exec("show system memory");
        if ($data && $data =~ /(\d+)%/) {
            return "Memory: $1% used\n";
        }
    };
    
    return "Memory: Unable to retrieve\n";
}

sub read_device_file {
    my ($file) = @_;
    
    open my $fh, '<', $file or die "Cannot read device file '$file': $!\n";
    
    my @devices;
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^\s*#/;
        push @devices, $_;
    }
    
    close $fh;
    return @devices;
}
```