#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Localtime;

=head1 interface_error_analyzer.pl
Analyzes interface error statistics on network devices via SSH.
Collects input/output errors, CRC errors, drops, and reports on problematic interfaces.

Usage:
  perl interface_error_analyzer.pl --host 10.1.1.1 --user admin --password pass [options]
  perl interface_error_analyzer.pl --hostfile devices.txt --user admin --password pass [options]

Prerequisites:
  - Net::SSH::Expect Perl module
  - SSH access to network devices
  - Devices must support 'show interfaces' command (Cisco IOS/IOS-XE)

Options:
  --host           Target device IP/hostname
  --hostfile       File containing device IPs (one per line)
  --user           SSH username
  --password       SSH password
  --log            Optional log file (default: stdout only)
  --error-threshold   Alert if input errors > this value (default: 100)
  --crc-threshold     Alert if CRC errors > this value (default: 50)
  --timeout           SSH connection timeout in seconds (default: 10)

=cut

my ($host, $hostfile, $user, $password, $logfile);
my ($error_threshold, $crc_threshold, $timeout) = (100, 50, 10);

GetOptions(
    'host=s'         => \$host,
    'hostfile=s'     => \$hostfile,
    'user=s'         => \$user,
    'password=s'     => \$password,
    'log=s'          => \$logfile,
    'error-threshold=i' => \$error_threshold,
    'crc-threshold=i'   => \$crc_threshold,
    'timeout=i'      => \$timeout,
) or usage();

sub usage {
    print "Usage: $0 --host <ip> --user <user> --password <pass> [options]\n";
    print "       $0 --hostfile <file> --user <user> --password <pass> [options]\n";
    exit 1;
}

die "Must specify --host or --hostfile\n" unless ($host || $hostfile);
die "Must specify --user and --password\n" unless ($user && $password);

my @devices = ();
if ($host) {
    @devices = ($host);
} else {
    open my $fh, '<', $hostfile or die "Cannot open $hostfile: $!\n";
    while (<$fh>) {
        chomp;
        next if /^#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

my $logfh;
if ($logfile) {
    open $logfh, '>>', $logfile or die "Cannot open log file $logfile: $!\n";
}

sub log_msg {
    my ($msg) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    my $entry = "[$ts] $msg";
    print "$entry\n";
    print $logfh "$entry\n" if $logfh;
}

sub analyze_device {
    my ($device_ip) = @_;
    
    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host => $device_ip,
            user => $user,
            password => $password,
            timeout => $timeout,
            raw_pty => 1,
        );
        $ssh->login();
    };
    
    if ($@) {
        log_msg("ERROR: Cannot connect to $device_ip - $@");
        return;
    }
    
    log_msg("INFO: Connected to $device_ip - analyzing interfaces");
    
    eval {
        $ssh->send("terminal length 0");
        $ssh->read_all();
        
        $ssh->send("show interfaces");
        my $output = $ssh->read_all();
        
        my @lines = split /\n/, $output;
        my $current_int = "";
        my %stats = (errors => 0, crc => 0, drops => 0);
        
        foreach my $line (@lines) {
            if ($line =~ /^(\S+)\s+is\s+(?:up|down)/) {
                if ($current_int && ($stats{errors} > $error_threshold || $stats{crc} > $crc_threshold)) {
                    log_msg("ALERT: $device_ip $current_int - errors=$stats{errors} crc=$stats{crc}");
                }
                $current_int = $1;
                %stats = (errors => 0, crc => 0, drops => 0);
            }
            
            $stats{errors} = $1 if $line =~ /(\d+)\s+input errors/;
            $stats{crc} = $1 if $line =~ /(\d+)\s+CRC/;
            $stats{drops} = $1 if $line =~ /(\d+)\s+(?:input|output)\s+drops/;
        }
        
        if ($current_int && ($stats{errors} > $error_threshold || $stats{crc} > $crc_threshold)) {
            log_msg("ALERT: $device_ip $current_int - errors=$stats{errors} crc=$stats{crc}");
        }
        
        $ssh->send("exit");
        $ssh->close();
    };
    
    if ($@) {
        log_msg("ERROR: Analysis failed for $device_ip - $@");
    }
}

foreach my $device (@devices) {
    analyze_device($device);
}

close $logfh if $logfh;
log_msg("INFO: Interface error analysis completed successfully");
exit 0;