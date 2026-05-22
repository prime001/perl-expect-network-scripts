```perl
#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;

# DEVICE RESOURCE MONITOR - Network Health Check via SSH
# Purpose: Monitor CPU, memory utilization on network devices
# Usage: ./095_device_resource_monitor.pl --device 192.168.1.1 --user admin --pass password
#        ./095_device_resource_monitor.pl --file devices.txt --logfile health.log
# Prerequisites: Net::SSH::Expect, SSH access, appropriate privilege level
# Notes: Thresholds - CPU >80%, Memory >85% trigger alerts
#        Batch mode with --file (one device per line, use # for comments)

my ($device, $user, $password, $device_file, $logfile, $timeout, $port);
GetOptions(
    'device=s' => \$device,
    'user=s' => \$user,
    'pass=s' => \$password,
    'file=s' => \$device_file,
    'logfile=s' => \$logfile,
    'timeout=i' => \$timeout,
    'port=i' => \$port,
) or die "Error in command line arguments\n";

$user //= 'admin';
$timeout //= 20;
$port //= 22;

die "Must specify --device or --file\n" unless ($device || $device_file);

my @devices = $device ? ($device) : read_devices($device_file);
my $logfh;
if ($logfile) {
    open($logfh, '>>', $logfile) or die "Cannot open $logfile: $!\n";
}

foreach my $host (@devices) {
    check_device($host, $user, $password, $timeout, $port, $logfh);
}

close($logfh) if $logfh;

sub check_device {
    my ($host, $user, $pass, $timeout, $port, $logfh) = @_;
    print "[*] Monitoring $host\n";
    log_msg($logfh, "[*] Monitoring $host");
    
    my $ssh = Net::SSH::Expect->new(
        host => $host,
        user => $user,
        password => $pass,
        port => $port,
        timeout => $timeout,
        raw_pty => 1,
    );
    
    eval { $ssh->login(); };
    if ($@) {
        print "  [!] Connection failed: $@\n";
        log_msg($logfh, "  [!] Connection failed to $host");
        return;
    }
    
    eval { $ssh->send("terminal length 0"); $ssh->waitfor('.*#', $timeout); };
    
    my $cpu = get_metric($ssh, "show processes cpu | include CPU utilization",
                        'CPU utilization[^:]*:\s*(\d+)%', $timeout);
    my $mem = get_metric($ssh, "show memory",
                        'Processor.*?(\d+)%\s+used', $timeout);
    my $ver = get_metric($ssh, "show version",
                        'Cisco IOS Software.*?Version\s+(\S+)', $timeout);
    
    $cpu //= 0;
    $mem //= 0;
    $ver //= 'Unknown';
    
    my $status = "OK";
    $status = "WARN" if ($cpu > 80 || $mem > 85);
    
    my $result = sprintf "  [%s] %s - CPU: %d%% | Memory: %d%%",
        $status, $ver, $cpu, $mem;
    
    print "$result\n";
    log_msg($logfh, $result);
    
    eval { $ssh->send("exit"); $ssh->waitfor('.*', 1); };
}

sub get_metric {
    my ($ssh, $cmd, $pattern, $timeout) = @_;
    my $result;
    eval {
        $ssh->send($cmd);
        my $output = $ssh->waitfor('.*#', $timeout);
        $result = $1 if $output =~ /$pattern/;
    };
    return $result;
}

sub read_devices {
    my ($file) = @_;
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    my @devices;
    while (my $line = <$fh>) {
        chomp($line);
        $line =~ s/#.*//;
        $line =~ s/^\s+|\s+$//g;
        push @devices, $line if $line;
    }
    close($fh);
    return @devices;
}

sub log_msg {
    my ($fh, $msg) = @_;
    return unless $fh;
    my $timestamp = scalar(localtime);
    print $fh "[$timestamp] $msg\n";
}
```