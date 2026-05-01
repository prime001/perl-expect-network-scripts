```perl
#!/usr/bin/perl
# Device Health Check - collects CPU, memory, uptime, temperature from network devices
# Usage: device_health_check.pl <host> | -f devices.txt [-o output.log]
# Requirements: Perl 5.10+, Net::SSH::Expect, SSH access with sufficient privileges

use strict;
use warnings;
use Getopt::Long;
use Net::SSH::Expect;
use Time::HiRes qw(time);

my ($device_file, $output_file, $username, $password, $timeout);
my $single_host = shift @ARGV if @ARGV && $ARGV[0] !~ /^-/;

GetOptions(
    'f|file=s'    => \$device_file,
    'o|output=s'  => \$output_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    't|timeout=i' => \$timeout,
) or die "Error in command line arguments\n";

$output_file ||= 'health_check.log';
$username    ||= $ENV{NETDEV_USER} || 'admin';
$password    ||= $ENV{NETDEV_PASS} || 'password';
$timeout     ||= 30;

my @devices;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    @devices = grep { chomp; $_ } <$fh>;
    close $fh;
} elsif ($single_host) {
    @devices = ($single_host);
} else {
    die "Usage: $0 <host> | -f <file> [-o <output>] [-u <user>] [-p <pass>] [-t <timeout>]\n";
}

die "No devices specified\n" unless @devices;

open my $log, '>>', $output_file or die "Cannot open $output_file: $!\n";

foreach my $device (@devices) {
    next unless $device;
    print "\n[$device] Connecting...\n";
    print $log "\n" . ("=" x 70) . "\n";
    print $log "Device: $device\n";
    print $log "Timestamp: " . scalar(localtime) . "\n";
    print $log ("=" x 70) . "\n";
    
    my $start = time();
    my $ssh = Net::SSH::Expect->new(
        host    => $device,
        user    => $username,
        password=> $password,
        timeout => $timeout,
        raw_pty => 1,
    );
    
    eval {
        $ssh->login() or die "SSH login failed\n";
        
        # Disable paging on Cisco devices
        $ssh->exec_cmd('terminal length 0');
        $ssh->exec_cmd('terminal width 0');
        
        # Collect version and uptime
        my $version = $ssh->exec_cmd('show version');
        if ($version =~ /System uptime is (.+?)[\r\n]/i) {
            print "  Uptime: $1\n";
            print $log "Uptime: $1\n";
        }
        
        # CPU utilization
        my $proc = $ssh->exec_cmd('show processes cpu');
        if ($proc =~ /CPU utilization[^:]*:\s*(\d+)%/i) {
            print "  CPU Utilization: $1%\n";
            print $log "CPU Utilization: $1%\n";
        }
        
        # Memory usage
        my $mem = $ssh->exec_cmd('show memory');
        if ($mem =~ /Processor\s+Pool\s+Total\s+(\d+)(?:\s+Used\s+(\d+))?/is) {
            my $total = $1;
            if ($mem =~ /Free\s+(\d+)/i) {
                my $free = $1;
                my $pct = int(100 * ($total - $free) / $total);
                print "  Memory: ${pct}% used\n";
                print $log "Memory: ${pct}% used\n";
            }
        }
        
        # Temperature sensors
        my $env = $ssh->exec_cmd('show environment');
        my $temp_count = 0;
        while ($env =~ /(?:Temperature|Temp):\s*([0-9.]+)\s*(?:C|°C|degrees)/ig) {
            print "  Temperature: $1°C\n" if $temp_count == 0;
            print $log "Temperature: $1°C\n" if $temp_count == 0;
            $temp_count++;
        }
        
        # Interface status summary
        my $intf = $ssh->exec_cmd('show interfaces summary');
        if ($intf =~ /(\d+)\s+Shutdown/i) {
            print "  Shutdown Interfaces: $1\n";
            print $log "Shutdown Interfaces: $1\n";
        }
        
        # Log full output for troubleshooting
        print $log "\n--- Full Output ---\n";
        print $log "VERSION:\n$version\n";
        print $log "\nPROCESSES:\n$proc\n";
        print $log "\nMEMORY:\n$mem\n";
        
        $ssh->close();
        print "  Connected successfully\n";
    };
    
    if ($@) {
        my $error = $@;
        chomp $error;
        print "  ERROR: $error\n";
        print $log "ERROR: $error\n";
    }
    
    my $elapsed = int((time() - $start) * 1000);
    print "  Completed in ${elapsed}ms\n";
    print $log "Duration: ${elapsed}ms\n";
}

close $log;
print "\n" . ("=" x 70) . "\n";
print "Health check complete. Results saved to: $output_file\n";
exit 0;
```