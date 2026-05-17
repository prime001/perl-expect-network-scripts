```perl
#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Localtime;

=head1 DEVICE HEALTH MONITOR

Monitors device health metrics (uptime, CPU, memory) via SSH.
Connects to network devices, executes health check commands,
and logs results to both STDOUT and a log file.

Usage:
  device_health.pl --host 192.168.1.1 --user admin --password pass [--log health.log]
  device_health.pl --file devices.txt --user admin --password pass
  
Arguments:
  --host           Single device hostname/IP
  --file           File with list of devices (one per line)
  --user           SSH username (required)
  --password       SSH password (required)
  --log            Output log file (optional, default: device_health.log)
  --timeout        SSH timeout in seconds (default: 10)

Prerequisites:
  - Net::SSH::Expect Perl module
  - SSH access to network devices
  - Device prompt detection (cisco% or cisco#)

=cut

my ($host, $device_file, $user, $password, $logfile, $timeout);
GetOptions(
    'host=s'     => \$host,
    'file=s'     => \$device_file,
    'user=s'     => \$user,
    'password=s' => \$password,
    'log=s'      => \$logfile,
    'timeout=i'  => \$timeout,
) or die "Error in command line arguments\n";

$logfile ||= 'device_health.log';
$timeout ||= 10;
die "Username required (--user)\n" unless $user;
die "Password required (--password)\n" unless $password;
die "Provide --host or --file\n" unless $host || $device_file;

my @devices = $host ? ($host) : read_device_file($device_file);
die "No devices specified\n" unless @devices;

open(my $log_fh, '>>', $logfile) or die "Cannot open $logfile: $!\n";
log_msg($log_fh, "=== Health Check Started ===");

foreach my $device (@devices) {
    check_device_health($device, $user, $password, $timeout, $log_fh);
}

log_msg($log_fh, "=== Health Check Completed ===");
close($log_fh);
print "Results logged to $logfile\n";

sub check_device_health {
    my ($dev, $usr, $pwd, $tout, $lfh) = @_;
    
    print "Checking $dev... ";
    log_msg($lfh, "\nDevice: $dev");
    
    my $ssh = Net::SSH::Expect->new(
        host => $dev,
        user => $usr,
        password => $pwd,
        timeout => $tout,
        raw_pty => 1,
    );
    
    unless ($ssh->login()) {
        print "FAILED\n";
        log_msg($lfh, "  ERROR: SSH login failed");
        return;
    }
    
    # Execute show version to get uptime
    $ssh->send("show version");
    $ssh->waitfor('cisco#|cisco%', $tout) or return;
    my $version_output = $ssh->before();
    
    # Parse uptime from version output
    my ($uptime) = $version_output =~ /uptime is\s+([^\n]+)/i;
    if ($uptime) {
        print "OK\n";
        log_msg($lfh, "  Uptime: $uptime");
    } else {
        print "PARTIAL\n";
        log_msg($lfh, "  Uptime: Unable to parse");
    }
    
    # Try to get CPU/memory for Cisco devices
    $ssh->send("show processes cpu");
    $ssh->waitfor('cisco#|cisco%', $tout) or goto CLOSE;
    my $cpu_output = $ssh->before();
    
    my ($cpu_usage) = $cpu_output =~ /CPU utilization for five seconds:\s+(\d+)%/i;
    log_msg($lfh, "  CPU 5sec: " . ($cpu_usage ? "$cpu_usage%" : "N/A"));
    
    $ssh->send("show memory");
    $ssh->waitfor('cisco#|cisco%', $tout) or goto CLOSE;
    my $mem_output = $ssh->before();
    
    if ($mem_output =~ /Processor.*\n.*(\d+)\s+\d+\s+(\d+)/m) {
        my ($total, $free) = ($1, $2);
        my $used_pct = int(100 * ($total - $free) / $total);
        log_msg($lfh, "  Memory Usage: ${used_pct}%");
    }
    
CLOSE:
    $ssh->close();
}

sub read_device_file {
    my ($file) = @_;
    open(my $fh, '<', $file) or die "Cannot open $file: $!\n";
    my @devs = grep { chomp; $_ && !/^#/ } <$fh>;
    close($fh);
    return @devs;
}

sub log_msg {
    my ($fh, $msg) = @_;
    my $timestamp = scalar(localtime());
    my $log_line = "[$timestamp] $msg\n";
    print $log_line;
    print $fh $log_line;
}
```