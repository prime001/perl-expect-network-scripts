```perl
#!/usr/bin/perl
# Device Health Check Script - Collects CPU, Memory, Temperature, Uptime
# Useful for quick fleet health assessment across network devices
#
# USAGE:
#   device_health_check.pl -i 192.168.1.1 -u admin -p password [-l output.log]
#   device_health_check.pl -f devices.txt -u admin -p password [-l output.log]
#
# REQUIREMENTS:
#   - Net::SSH::Expect Perl module
#   - SSH access to IOS/IOS-XE network devices
#   - Valid SSH credentials
#
# PREREQUISITES:
#   Device file format (one device per line, # for comments):
#   192.168.1.1
#   core-router-02
#   # 192.168.1.3   (commented out)
#   switch-lab-04
#
# FEATURES:
#   - Handles connection timeouts and authentication failures
#   - Outputs results to STDOUT and optional log file
#   - Supports batch processing from file
#   - Comprehensive error handling with graceful failure
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Piece;

my ($device_ip, $device_file, $username, $password, $logfile, $timeout, $help);

GetOptions(
    'ip|i=s'      => \$device_ip,
    'file|f=s'    => \$device_file,
    'user|u=s'    => \$username,
    'pass|p=s'    => \$password,
    'log|l=s'     => \$logfile,
    'timeout|t=i' => \$timeout,
    'help|h'      => \$help,
) or die "Error in command line arguments\n";

if ($help || (!$device_ip && !$device_file) || !$username || !$password) {
    print "Usage: $0 -i <device_ip> -u <user> -p <pass> [-l logfile] [-t timeout]\n";
    print "       $0 -f <device_file> -u <user> -p <pass> [-l logfile] [-t timeout]\n";
    exit 1;
}

$timeout //= 10;

my @devices;
if ($device_ip) {
    push @devices, $device_ip;
} elsif ($device_file) {
    die "Device file not found: $device_file\n" unless -f $device_file;
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

my $logfh;
if ($logfile) {
    open $logfh, '>>', $logfile or die "Cannot open logfile: $!\n";
}

sub log_output {
    my ($msg) = @_;
    print $msg;
    print $logfh $msg if $logfh;
}

sub check_device_health {
    my ($host) = @_;
    
    log_output "[*] Connecting to $host...\n";
    
    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $host,
            user     => $username,
            password => $password,
            timeout  => $timeout,
            raw_pty  => 1,
        );
        
        my $login_result = $ssh->login();
        die "SSH login failed or timed out\n" 
            unless $login_result && $login_result !~ /Permission denied|Authentication failed|Timeout/i;
    };
    
    if ($@) {
        log_output "[!] Connection error on $host: $@";
        return 0;
    }
    
    eval {
        $ssh->exec("terminal length 0");
        $ssh->read_all();
        
        # Collect uptime
        my $version = $ssh->exec("show version | include uptime");
        if ($version =~ /uptime is\s+(.+?)[\r\n]/) {
            log_output "[+] $host - Uptime: $1\n";
        }
        
        # Collect CPU utilization
        my $cpu_out = $ssh->exec("show processes cpu sorted");
        if ($cpu_out =~ /CPU processes:\s+([0-9.]+)%/) {
            log_output "[+] $host - CPU: $1%\n";
        }
        
        # Collect memory usage
        my $mem_out = $ssh->exec("show memory | include Processor");
        if ($mem_out =~ /(\d+)%/) {
            log_output "[+] $host - Memory: $1%\n";
        }
        
        # Collect temperature readings
        my $temp_out = $ssh->exec("show environment temperature");
        my @temp_lines = split /\n/, $temp_out;
        my $temp_found = 0;
        foreach my $line (@temp_lines) {
            if ($line =~ /Temp|temp|TEMP/ && $line =~ /[0-9]/) {
                $line =~ s/^\s+|\s+$//g;
                log_output "[+] $host - Temp: $line\n" if length($line) > 5;
                $temp_found = 1;
            }
        }
        log_output "[+] $host - No temperature data available\n" unless $temp_found;
        
        $ssh->close();
        log_output "[*] $host - Health check completed successfully\n";
        return 1;
    };
    
    if ($@) {
        log_output "[!] Error executing commands on $host: $@";
        eval { $ssh->close() if $ssh; };
        return 0;
    }
}

my $timestamp = localtime->strftime('%Y-%m-%d %H:%M:%S');
log_output "===== Device Health Check Started: $timestamp =====\n";

my $success_count = 0;
foreach my $device (@devices) {
    $success_count += check_device_health($device);
}

log_output "===== Health Check Completed: $success_count/" . scalar(@devices) . " devices successful =====\n";
close $logfh if $logfh;

exit($success_count == scalar(@devices) ? 0 : 1);
```