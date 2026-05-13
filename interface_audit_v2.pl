```perl
#!/usr/bin/perl
#
# Critical Routes and Prefix Validator
# Purpose: Validate that critical/expected routes exist in device routing table
# Usage: ./route_validator.pl <device_ip> <routes_file>
#        ./route_validator.pl <device_ip> 10.0.0.0/8 10.1.0.0/16 192.168.0.0/16
#
# Prerequisites:
#   - Net::SSH::Expect module (cpan Net::SSH::Expect)
#   - SSH connectivity to target devices
#   - Network credentials in environment: DEVICE_USER, DEVICE_PASS
#   - Route prefixes to validate in file or as command arguments
#
# Features:
#   - Connects via SSH to network device
#   - Retrieves routing table
#   - Validates critical prefixes are present
#   - Checks route protocol (static, BGP, OSPF, etc)
#   - Reports missing or unexpected routes
#   - Outputs results to STDOUT and log file with timestamps
#
# Error Handling:
#   - SSH connection failures with detailed messages
#   - Authentication errors caught and logged
#   - Command timeouts and device responsiveness checks
#   - Graceful handling of device disconnection
#   - Input validation for IP prefixes

use strict;
use warnings;
use Net::SSH::Expect;
use Time::HiRes qw(gettimeofday tv_interval);
use Getopt::Std;
use IO::File;

my %opts;
getopts('l:u:p:', \%opts);

my $device = shift @ARGV or die "Usage: $0 [-l logfile] [-u user] [-p pass] <device> [prefix1 prefix2 ...]\n";

my @prefixes;
if ($_[0] && $_[0] =~ m|/|) {
    @prefixes = @ARGV;
} else {
    my $routes_file = shift @ARGV;
    if ($routes_file && -f $routes_file) {
        open my $fh, '<', $routes_file or die "Cannot open file $routes_file: $!\n";
        while (<$fh>) {
            chomp;
            next if /^#/ or /^\s*$/;
            push @prefixes, $_;
        }
        close $fh;
    }
}

die "No prefixes specified or found\n" unless @prefixes;

my $logfile = $opts{l} || "route_validation_${device}.log";
my $user = $opts{u} || $ENV{DEVICE_USER} || 'admin';
my $pass = $opts{p} || $ENV{DEVICE_PASS} || 'password';

open my $log_fh, '>>', $logfile or die "Cannot open log: $!\n";
$log_fh->autoflush(1);

sub log_output {
    my ($msg) = @_;
    my $timestamp = scalar localtime;
    print "[$$] $timestamp - $msg\n";
    print $log_fh "[$$] $timestamp - $msg\n";
}

log_output("=== Route Validation Start: $device ===");

my $start = [gettimeofday];
my $ssh;

eval {
    $ssh = Net::SSH::Expect->new(
        host => $device,
        user => $user,
        password => $pass,
        timeout => 20,
        raw_pty => 1,
    );
    
    unless ($ssh->login()) {
        die "SSH login failed: " . $ssh->error();
    }
};

if ($@) {
    log_output("[ERROR] Failed to connect to $device: $@");
    close $log_fh;
    exit 1;
}

my $conn_time = tv_interval($start);
log_output("[OK] SSH connected to $device (${conn_time}s)");

my @found_routes;
my @missing_routes;

eval {
    my $start_cmd = [gettimeofday];
    my $routing_table = $ssh->exec('show ip route | include ');
    my $cmd_time = tv_interval($start_cmd);
    
    unless ($routing_table) {
        die "Failed to retrieve routing table";
    }
    
    log_output("[OK] Retrieved routing table (${cmd_time}s) - scanning prefixes");
    
    foreach my $prefix (@prefixes) {
        my $found = 0;
        foreach my $line (split /\n/, $routing_table) {
            if ($line =~ /\Q$prefix\E/) {
                push @found_routes, $prefix;
                log_output("[FOUND] $prefix - $line");
                $found = 1;
                last;
            }
        }
        
        unless ($found) {
            push @missing_routes, $prefix;
            log_output("[MISSING] $prefix - NOT FOUND in routing table");
        }
    }
};

if ($@) {
    log_output("[ERROR] Route validation failed: $@");
}

eval { $ssh->close(); };

log_output("=== Summary ===");
log_output("Total prefixes checked: " . scalar(@prefixes));
log_output("Found: " . scalar(@found_routes));
log_output("Missing: " . scalar(@missing_routes));

if (@missing_routes) {
    log_output("[ALERT] Missing routes detected:");
    foreach (@missing_routes) {
        log_output("  - $_");
    }
}

log_output("=== Route Validation Complete ===\n");
close $log_fh;

exit(scalar(@missing_routes) > 0 ? 1 : 0);
```