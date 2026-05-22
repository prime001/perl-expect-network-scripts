#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::HiRes qw(time);

=head1 NAME
interface_error_monitor.pl - Monitor interface errors and status across network devices

=head1 SYNOPSIS
./interface_error_monitor.pl -host <ip|hostname> [-user <username>] [-pass <password>] [-file <device_list>] [-log <logfile>]

=head1 DESCRIPTION
Connects to network device(s) via SSH and monitors interface health by collecting:
- Interface operational status (up/down)
- Error counters (CRC, runts, giants, collisions)
- Discard counters (input/output drops)
- Interface statistics and anomalies

Useful for network monitoring, NOC operations, and troubleshooting interface issues.
Can process single device or read multiple devices from file (one per line).

=head1 PREREQUISITES
- Net::SSH::Expect module
- Expect installed
- SSH access to Cisco devices (IOS/IOS-XE/IOS-XR)
- Device credentials (SSH username/password)

=head1 EXAMPLES
./interface_error_monitor.pl -host 192.168.1.1 -user admin -pass secret
./interface_error_monitor.pl -file devices.txt -user netadmin -log interface_report.log
./interface_error_monitor.pl -host router.local -user netadmin

=head1 EXIT CODES
0 = Success
1 = Connection or authentication error
2 = Device unreachable
3 = Invalid input arguments

=cut

my ($host, $user, $pass, $devicefile, $logfile, $timeout);
GetOptions(
    'host=s'    => \$host,
    'file=s'    => \$devicefile,
    'user=s'    => \$user,
    'pass=s'    => \$pass,
    'log=s'     => \$logfile,
    'timeout=i' => \$timeout,
) or die "Usage: $0 -host <ip|hostname> | -file <device_list> [-user <username>] [-pass <password>] [-log <logfile>]\n";

die "Usage: Specify either -host or -file argument\n" unless ($host || $devicefile);

$user    //= 'admin';
$pass    //= $ENV{DEVICE_PASSWORD} || '';
$timeout //= 20;

my @devices = ();
if ($devicefile) {
    open my $fh, '<', $devicefile or die "Cannot open device file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/;
        next if /^\s*$/;
        push @devices, $_;
    }
    close $fh;
} else {
    push @devices, $host;
}

sub log_msg {
    my ($msg) = @_;
    print $msg;
    if ($logfile) {
        open my $fh, '>>', $logfile or warn "Cannot write to $logfile: $!\n";
        print $fh $msg;
        close $fh;
    }
}

sub check_device {
    my ($device_ip) = @_;
    my $start = time();
    
    my $ssh = Net::SSH::Expect->new(
        host     => $device_ip,
        user     => $user,
        password => $pass,
        timeout  => $timeout,
        raw_pty  => 1,
    );
    
    eval {
        $ssh->login() or die "SSH login failed\n";
        
        log_msg "\n" . "=" x 70 . "\n";
        log_msg "Device: $device_ip\n";
        log_msg "=" x 70 . "\n";
        
        $ssh->send("terminal length 0");
        $ssh->waitfor('timeout' => $timeout, 'match' => '/[>#]/');
        
        # Get device name
        $ssh->send("show running-config | include hostname");
        my $hostname_out = $ssh->waitfor('timeout' => $timeout, 'match' => '/[>#]/');
        if ($hostname_out =~ /hostname\s+(\S+)/) {
            log_msg "Hostname: $1\n";
        }
        
        # Get interface status summary
        $ssh->send("show interface summary");
        my $summary = $ssh->waitfor('timeout' => $timeout, 'match' => '/[>#]/');
        log_msg "\nInterface Status Summary:\n";
        foreach my $line (split /\n/, $summary) {
            next unless $line =~ /\d+.*\d+/;
            log_msg "  $line\n";
        }
        
        # Get detailed interface errors
        $ssh->send("show interface | include (^[A-Za-z], errors|input errors|output errors)");
        my $errors = $ssh->waitfor('timeout' => $timeout, 'match' => '/[>#]/');
        
        my @error_lines = grep { /\d+\s+errors?/i || /^\s*\d+ (input|output|CRC|runt|giant)/ } split /\n/, $errors;
        
        if (@error_lines > 0) {
            log_msg "\nInterfaces with Errors/Discards:\n";
            foreach my $line (@error_lines) {
                $line =~ s/^\s+|\s+$//g;
                log_msg "  $line\n" if $line;
            }
        } else {
            log_msg "\nNo interface errors detected.\n";
        }
        
        # Check for down interfaces
        $ssh->send("show interface brief | include down");
        my $down_intf = $ssh->waitfor('timeout' => $timeout, 'match' => '/[>#]/');
        
        if ($down_intf && $down_intf !~ /^\s*$/) {
            log_msg "\nDown Interfaces:\n";
            foreach my $line (split /\n/, $down_intf) {
                next if $line =~ /^Interface|---/;
                log_msg "  $line\n" if $line =~ /\S/;
            }
        }
        
        # Get CRC and collision errors
        $ssh->send("show interface | include (CRC|collision|runts|giants)");
        my $crc_out = $ssh->waitfor('timeout' => $timeout, 'match' => '/[>#]/');
        
        my @crc_lines = grep { /\d+/ && !/^\s*$/ } split /\n/, $crc_out;
        if (@crc_lines > 0) {
            log_msg "\nDetailed Error Counters:\n";
            foreach my $line (@crc_lines) {
                $line =~ s/^\s+|\s+$//g;
                log_msg "  $line\n" if $line;
            }
        }
        
        $ssh->close();
        
        my $elapsed = time() - $start;
        log_msg "\nCompleted in " . sprintf("%.2f", $elapsed) . "s\n";
        return 1;
        
    } or do {
        my $error = $@;
        log_msg "\n[ERROR] Failed to check device: $error\n";
        return 0;
    };
}

log_msg "[START] Interface Error Monitor - " . scalar(localtime) . "\n";
log_msg "Monitoring " . scalar(@devices) . " device(s)\n";

my $success_count = 0;
my $fail_count = 0;

foreach my $dev (@devices) {
    if (check_device($dev)) {
        $success_count++;
    } else {
        $fail_count++;
    }
}

log_msg "\n" . "=" x 70 . "\n";
log_msg "Summary: $success_count successful, $fail_count failed\n";
log_msg "[END] " . scalar(localtime) . "\n";

exit ($fail_count > 0 ? 1 : 0);