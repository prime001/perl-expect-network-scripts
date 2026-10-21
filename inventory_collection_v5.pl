```perl
#!/usr/bin/perl
# CDP and LLDP Neighbor Discovery Script
# Purpose: Discover and document directly connected devices via CDP/LLDP protocols
# Usage: ./neighbor_discovery.pl <device_ip> [--logfile=neighbors.txt]
#        ./neighbor_discovery.pl devices.txt [--logfile=neighbors.txt]
# Prerequisites: Net::SSH::Expect module, SSH credentials in ~/.ssh/config or environment
# Environment: NET_USER and NET_PASS can override defaults

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::HiRes qw(usleep);

my %config = (
    username => $ENV{NET_USER} || 'admin',
    password => $ENV{NET_PASS} || 'password',
    port => 22,
    timeout => 20,
    raw_pty => 1,
);

my ($logfile, $help);
GetOptions(
    'logfile=s' => \$logfile,
    'user=s' => \$config{username},
    'pass=s' => \$config{password},
    'port=i' => \$config{port},
    'help' => \$help,
) or die "Error in command line arguments\n";

if ($help || !@ARGV) {
    print "Usage: $0 <device_ip|file> [--logfile=output.txt] [--user=admin] [--pass=pass] [--port=22]\n";
    print "  Discovers CDP/LLDP neighbors for topology mapping\n";
    exit 0;
}

sub log_output {
    my ($msg) = @_;
    print $msg;
    if ($logfile) {
        open my $fh, '>>', $logfile or warn "Cannot open logfile: $!";
        print $fh $msg;
        close $fh;
    }
}

sub discover_neighbors {
    my ($device) = @_;
    my $success = 0;
    
    eval {
        my $ssh = Net::SSH::Expect->new(
            host => $device,
            user => $config{username},
            password => $config{password},
            port => $config{port},
            timeout => $config{timeout},
            raw_pty => $config{raw_pty},
        );
        
        die "Login failed" unless $ssh->login();
        
        log_output("\n" . "=" x 70 . "\n");
        log_output("Device: $device | Time: " . scalar localtime . "\n");
        log_output("=" x 70 . "\n");
        
        my $hostname = $ssh->exec("show running-config | include hostname");
        log_output("Hostname: $hostname\n") if $hostname;
        
        my $cdp_output = $ssh->exec("show cdp neighbors detail");
        if ($cdp_output && $cdp_output !~ /^%/m) {
            log_output("\n--- CDP NEIGHBORS ---\n");
            log_output("$cdp_output\n");
        } else {
            log_output("CDP: No neighbors or CDP disabled\n");
        }
        
        my $lldp_output = $ssh->exec("show lldp neighbors detail");
        if ($lldp_output && $lldp_output !~ /^%/m) {
            log_output("\n--- LLDP NEIGHBORS ---\n");
            log_output("$lldp_output\n");
        }
        
        $ssh->close();
        $success = 1;
        log_output("Status: SUCCESS\n");
        
    };
    
    if ($@) {
        log_output("Status: FAILED\n");
        log_output("Error: $@\n");
        $success = 0;
    }
    
    return $success;
}

my @devices;
if (-f $ARGV[0]) {
    open my $fh, '<', $ARGV[0] or die "Cannot open file $ARGV[0]: $!\n";
    @devices = grep { chomp; $_ =~ /\S/ } <$fh>;
    close $fh;
} else {
    @devices = @ARGV;
}

log_output("Neighbor Discovery Started: " . scalar localtime . "\n");
log_output("Devices to query: " . scalar(@devices) . "\n");

my $successful = 0;
my $failed = 0;

foreach my $device (@devices) {
    $device =~ s/^\s+|\s+$//g;
    next unless $device;
    
    if (discover_neighbors($device)) {
        $successful++;
    } else {
        $failed++;
    }
    
    usleep(1000000);
}

log_output("\n" . "=" x 70 . "\n");
log_output("Discovery Summary\n");
log_output("=" x 70 . "\n");
log_output("Total Devices: " . scalar(@devices) . "\n");
log_output("Successful: $successful\n");
log_output("Failed: $failed\n");
log_output("Completion Time: " . scalar localtime . "\n");

exit $failed ? 1 : 0;
```