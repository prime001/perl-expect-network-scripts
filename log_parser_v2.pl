#!/usr/bin/perl
#
# Device Health Monitor
#
# Purpose: Collect CPU, memory, and uptime metrics from network devices via SSH
# Usage: ./device_health_monitor.pl -h <hostname> [-u <user>] [-p <password>] [-l <logfile>]
#        ./device_health_monitor.pl -f <device_list> [-u <user>] [-p <password>] [-l <logfile>]
#
# Prerequisites:
#   - Net::SSH::Expect Perl module (cpan Net::SSH::Expect)
#   - SSH access to network devices with enable mode
#   - Device must run Cisco IOS, IOS-XE, IOS-XR, or NX-OS
#
# Output: Prints metrics to STDOUT; appends timestamped results to logfile if specified
# Example: perl device_health_monitor.pl -h 192.168.1.1 -u admin -p mypass -l health.log
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($hostname, $username, $password, $logfile, $device_file);
my $timeout = 30;

GetOptions(
    'h|host=s'     => \$hostname,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$logfile,
    'f|file=s'     => \$device_file,
    't|timeout=i'  => \$timeout,
) or die "Error in command line arguments\n";

die "Must specify either -h <hostname> or -f <device_file>\n" 
    unless ($hostname || $device_file);

$username ||= prompt_input("SSH Username: ");
$password ||= prompt_input("SSH Password: ", 1);

my @devices;
if ($hostname) {
    push @devices, $hostname;
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open $logfile: $!\n";
}

print "Device Health Monitor\n" . "=" x 70 . "\n";

foreach my $device (@devices) {
    collect_health($device, $username, $password, $log_fh);
}

close $log_fh if $log_fh;
print "\nComplete.\n";

sub collect_health {
    my ($host, $user, $pass, $log) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    
    print "\n[$ts] Connecting to $host...";
    
    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        password   => $pass,
        user       => $user,
        timeout    => $timeout,
        raw_pty    => 1,
    );
    
    my $login_output;
    eval { $login_output = $ssh->login(); };
    
    if ($@ || !$login_output) {
        my $error = "FAILED: Connection error";
        print " $error\n";
        print $log "$ts | $host | $error\n" if $log;
        return;
    }
    print " OK\n";
    
    $ssh->exec_cmd("terminal length 0");
    
    my %metrics = ();
    
    eval {
        my $version_output = $ssh->exec_cmd("show version");
        if ($version_output =~ /[Uu]ptime is (.+?)(?:\n|$)/) {
            $metrics{uptime} = $1;
        } elsif ($version_output =~ /[Ss]ystem [Uu]ptime is (.+?)(?:\n|$)/) {
            $metrics{uptime} = $1;
        }
        
        my $cpu_output = $ssh->exec_cmd("show processes cpu | include CPU utilization");
        if ($cpu_output =~ /CPU utilization[^:]*:\s+([\d.]+)%/) {
            $metrics{cpu} = $1;
        }
        
        my $mem_output = $ssh->exec_cmd("show memory | include Processor");
        if ($mem_output =~ /Processor.*?(\d+)K\s+total.*?(\d+)K\s+used/) {
            my $total = $1;
            my $used = $2;
            $metrics{mem_pct} = sprintf("%.1f", ($used / $total) * 100);
        }
    };
    
    if ($@) {
        my $error = "FAILED: Command execution error";
        print "  $error: $@\n";
        print $log "$ts | $host | $error\n" if $log;
        $ssh->close();
        return;
    }
    
    my $cpu_str = defined $metrics{cpu} ? sprintf("%5.1f%%", $metrics{cpu}) : "  N/A ";
    my $mem_str = defined $metrics{mem_pct} ? sprintf("%5.1f%%", $metrics{mem_pct}) : "  N/A ";
    my $uptime_str = $metrics{uptime} || "N/A";
    
    my $result = sprintf("  %-18s CPU: %s | Memory: %s | Uptime: %s", 
        $host, $cpu_str, $mem_str, $uptime_str);
    
    print $result . "\n";
    print $log "$ts | $result\n" if $log;
    
    $ssh->close();
}

sub prompt_input {
    my ($prompt, $hidden) = @_;
    print $prompt;
    system("stty -echo") if $hidden;
    my $input = <STDIN>;
    system("stty echo") if $hidden;
    print "\n" if $hidden;
    chomp $input;
    return $input;
}