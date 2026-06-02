#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Piece;

=head1 TRANSCEIVER/OPTICS STATUS MONITOR

Monitors SFP/QSFP transceiver module status on network devices. Detects 
module failures, missing modules, temperature alarms, and optical signal 
issues. Proactively identifies failing optics before they cause outages.

USAGE:
  transceiver_monitor.pl --host 192.168.1.1 --user admin --pass password [--log output.log]
  transceiver_monitor.pl --file devices.txt --user admin --pass password

PREREQUISITES:
  - Perl Net::SSH::Expect module
  - SSH access to Cisco IOS/IOS-XE devices
  - Read access to transceiver data

=cut

my ($host, $file, $user, $pass, $logfile, $timeout);
GetOptions(
    'host=s'    => \$host,
    'file=s'    => \$file,
    'user=s'    => \$user,
    'pass=s'    => \$pass,
    'log=s'     => \$logfile,
    'timeout=i' => \$timeout,
) or die "Error in command line arguments\n";

$timeout //= 30;

die "Error: Specify --host or --file argument\n" unless ($host || $file);
die "Error: Username and password required\n" unless ($user && $pass);

my @devices = $host ? ($host) : get_devices_from_file($file);
die "Error: No devices found\n" unless @devices;

open my $logfh, '>>', $logfile or warn "Cannot open logfile $logfile: $!\n" if $logfile;

foreach my $device (@devices) {
    process_device($device, $user, $pass, $timeout, $logfh);
}

close $logfh if $logfh;
print "\nTransceiver monitoring complete\n";

sub get_devices_from_file {
    my ($file) = @_;
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    my @list;
    while (<$fh>) {
        chomp;
        next if /^#/ || /^\s*$/;
        push @list, $_;
    }
    close $fh;
    return @list;
}

sub process_device {
    my ($device, $user, $pass, $timeout, $logfh) = @_;
    my $time = Time::Piece::localtime->strftime('%Y-%m-%d %H:%M:%S');
    my $header = "\n[$time] Device: $device\n";
    print $header;
    print $logfh $header if $logfh;
    
    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $user,
        password => $pass,
        timeout  => $timeout,
        raw_pty  => 0,
    );
    
    eval {
        $ssh->login() or die "SSH login failed\n";
        $ssh->send("terminal length 0");
        $ssh->waitfor('.*#', 5);
        
        my $output = $ssh->exec('show interfaces transceiver brief 2>/dev/null');
        
        if (!$output || $output =~ /Invalid command|not available/) {
            $output = $ssh->exec('show inventory | include Transceiver');
        }
        
        if ($output && length($output) > 20) {
            my $alert_count = 0;
            foreach my line (split /\n/, $output) {
                next if $line =~ /^Interface|^---/ || $line =~ /^\s*$/;
                
                if ($line =~ /NOTINSERTED|NotPresent|FAILED|ALARM|ABSENT|no.*module/i) {
                    print "  ALERT: $line\n";
                    print $logfh "  ALERT: $line\n" if $logfh;
                    $alert_count++;
                } elsif ($line && $line !~ /show interfaces/) {
                    print "  OK: $line\n";
                    print $logfh "  OK: $line\n" if $logfh;
                }
            }
            print "  Status: $alert_count alerts found\n" if $alert_count;
        } else {
            print "  INFO: No transceiver data (command unsupported on this device)\n";
            print $logfh "  INFO: No transceiver data\n" if $logfh;
        }
        
        $ssh->close();
    };
    
    if ($@) {
        my $err = "  ERROR: $@";
        print $err;
        print $logfh $err if $logfh;
    }
}