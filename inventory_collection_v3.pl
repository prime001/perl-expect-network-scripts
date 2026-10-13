```perl
#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::localtime;

=head1 NAME
interface_statistics_collector.pl - Collect detailed interface error statistics from network devices

=head1 SYNOPSIS
./interface_statistics_collector.pl --device <host> [--user admin] [--pass password] [--log file.csv]
./interface_statistics_collector.pl --file devices.txt [--user admin] [--pass password] [--log stats.csv]

=head1 DESCRIPTION
Connects to Cisco IOS/IOS-XE network devices via SSH and collects interface error statistics
(CRC errors, runts, collisions, discards) for capacity planning and troubleshooting. Outputs
to STDOUT and optionally appends CSV data for trend analysis.

=head1 REQUIRES
Net::SSH::Expect module and SSH access to target devices

=cut

my ($device_arg, $device_file, $username, $password, $logfile, $timeout, $port);
GetOptions(
    'device=s'  => \$device_arg,
    'file=s'    => \$device_file,
    'user=s'    => \$username,
    'pass=s'    => \$password,
    'log=s'     => \$logfile,
    'timeout=i' => \$timeout,
    'port=i'    => \$port,
) or die "Error in arguments\n";

$username //= 'admin';
$password //= 'admin';
$timeout  //= 15;
$port     //= 22;

die "Specify --device <host> or --file <devices.txt>\n" 
    unless $device_arg || $device_file;

my @targets = $device_file ? read_device_file($device_file) : ($device_arg);

print "Interface Statistics Collector\n";
print "Started: " . scalar(localtime()) . "\n\n";

foreach my $target (@targets) {
    next unless $target =~ /\S/;
    collect_interface_stats($target, $username, $password, $timeout, $port, $logfile);
}

print "\nCompleted at " . scalar(localtime()) . "\n";
exit 0;

sub read_device_file {
    my ($file) = @_;
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    my @devices = grep { chomp; /\S/ } <$fh>;
    close $fh;
    return @devices;
}

sub collect_interface_stats {
    my ($host, $user, $pass, $timeout, $port, $logfile) = @_;
    
    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $user,
        password => $pass,
        timeout  => $timeout,
        raw_pty  => 1,
    );
    
    unless ($ssh->connect()) {
        print "[ERROR] $host: SSH connection failed\n";
        return;
    }
    
    eval {
        $ssh->waitfor('[#>]', undef);
        
        # Get hostname
        my @lines = $ssh->exec('show running-config | include ^hostname');
        my $hostname = ($lines[0] =~ /hostname\s+(\S+)/) ? $1 : $host;
        
        # Collect interface errors
        @lines = $ssh->exec('show interfaces | include "Internet address|CRC|runts|collisions|input errors|output errors"');
        
        print "[$hostname] Interface Error Statistics:\n";
        
        my $timestamp = time();
        my $interface = '';
        
        foreach my $line (@lines) {
            if ($line =~ /^(\S+)\s+is/) {
                $interface = $1;
            }
            
            if ($line =~ /(\d+)\s+input errors.*?(\d+)\s+CRC/) {
                my ($in_err, $crc) = ($1, $2);
                printf "  %-12s: Input Errors=%d, CRC=%d\n", $interface, $in_err, $crc;
                
                if ($logfile) {
                    log_statistics($logfile, $hostname, $interface, $in_err, $crc, $timestamp);
                }
            }
            
            if ($line =~ /(\d+)\s+collisions/) {
                printf "  %-12s: Collisions=%d\n", $interface, $1;
            }
        }
        
        $ssh->close();
    };
    
    if ($@) {
        print "[WARNING] $host: Execution error - $@\n";
    }
    
    print "\n";
}

sub log_statistics {
    my ($file, $hostname, $interface, $in_errors, $crc_errors, $timestamp) = @_;
    
    my $date = scalar(localtime($timestamp));
    my $write_header = !-e $file;
    
    open my $fh, '>>', $file or return;
    
    if ($write_header) {
        print $fh "Timestamp,Hostname,Interface,Input_Errors,CRC_Errors\n";
    }
    
    printf $fh "%s,%s,%s,%d,%d\n", $date, $hostname, $interface, $in_errors, $crc_errors;
    close $fh;
}
```