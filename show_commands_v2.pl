#!/usr/bin/perl
#
# Routing Table Analyzer - SSH-based device route auditor
#
# Purpose: Connect to network devices via SSH and audit the routing table
#   - Collects total route count and breakdown by protocol
#   - Validates default route presence
#   - Displays routing protocol summary
#   - Logs all results for compliance/audit trails
#
# Usage: perl route_audit.pl <device_ip> [username] [password]
#   or:  perl route_audit.pl devices.txt [username] [password]
#        (file format: one IP/hostname per line, # for comments)
#
# Prerequisites:
#   - Net::SSH::Expect module: cpan Net::SSH::Expect
#   - SSH connectivity to target devices
#   - User with route table viewing permissions
#
# Exit codes: 0=success, 1=arg error, 2=connection error
#

use strict;
use warnings;
use Net::SSH::Expect;
use Time::Piece;
use Getopt::Long;

die "Usage: $0 <device|device_file.txt> [username] [password]\n" if @ARGV < 1;

my ($device_input, $username, $password);
my @devices;

$device_input = shift @ARGV;
$username = shift @ARGV // 'admin';
$password = shift @ARGV;

unless ($password) {
    print "Enter password: ";
    system("stty -echo 2>/dev/null");
    chomp($password = <STDIN>);
    system("stty echo 2>/dev/null");
    print "\n";
}

if (-f $device_input) {
    open(my $fh, '<', $device_input) or die "Cannot open file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close($fh);
} else {
    @devices = ($device_input);
}

my $timestamp = Time::Piece::localtime->strftime("%Y%m%d_%H%M%S");
my $logfile = "route_audit_$timestamp.log";

open(my $log_fh, '>', $logfile) or die "Cannot create log: $!\n";

printf "Auditing %d device(s). Log: %s\n\n", scalar(@devices), $logfile;

my $success_count = 0;
foreach my $target (@devices) {
    $success_count++ if audit_device($target, $username, $password, $log_fh);
}

close($log_fh);
printf "\nCompleted: %d/%d devices successful\n", $success_count, scalar(@devices);

exit 0;

sub audit_device {
    my ($host, $user, $pass, $log) = @_;
    
    print "[$host] ";
    print $log "\n" . ("=" x 70) . "\n";
    print $log "Device: $host | Timestamp: " . Time::Piece::localtime->strftime("%Y-%m-%d %H:%M:%S") . "\n";
    
    my $ssh = Net::SSH::Expect->new(
        host => $host,
        user => $user,
        password => $pass,
        timeout => 15,
        raw_pty => 1,
    );
    
    unless (eval { $ssh->login() }) {
        print "FAILED (connection error)\n";
        print $log "ERROR: Connection failed - $@\n";
        return 0;
    }
    
    print "Connected... ";
    
    eval {
        $ssh->send("terminal length 0");
        $ssh->waitfor('[#>]', 10);
        
        $ssh->send("show ip route summary");
        my $summary = $ssh->waitfor('[#>]', 10);
        print $log "\n--- Route Summary ---\n$summary";
        
        $ssh->send("show ip route | include ^[A-Z*] | count");
        my $count_out = $ssh->waitfor('[#>]', 10);
        if ($count_out =~ /(\d+)/) {
            printf "Found %d routes\n", $1;
            print $log "\nTotal Routes: $1\n";
        }
        
        $ssh->send("show ip route 0.0.0.0/0");
        my $default = $ssh->waitfor('[#>]', 10);
        if ($default =~ /no route/i || $default =~ /not found/i) {
            print $log "WARNING: No default route\n";
        } else {
            print $log "Status: Default route present\n";
        }
        
        $ssh->close();
    };
    
    if ($@) {
        print "ERROR ($@)\n";
        print $log "ERROR: $@\n";
        return 0;
    }
    
    return 1;
}