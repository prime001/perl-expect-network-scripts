#!/usr/bin/perl
use strict;
use warnings;
use Expect;
use Getopt::Long;
use Time::localtime;

=head1 NAME
device_config_drift_detector.pl - Detect unauthorized configuration changes on network devices

=head1 SYNOPSIS
./device_config_drift_detector.pl --device <hostname|ip> [--username user] [--password pass] [--baseline]

=head1 DESCRIPTION
Captures and compares device running configurations to detect unauthorized changes.
Use --baseline on first run to establish baseline, then run periodically to detect
drift. Useful for compliance audits and change management. Results logged per-device.

=head1 USAGE EXAMPLES
Establish baseline:         ./device_config_drift_detector.pl --device 192.168.1.1 --baseline
Check for configuration drift: ./device_config_drift_detector.pl --device 192.168.1.1
Batch check from file:      while read ip; do ./device_config_drift_detector.pl --device $ip; done < devices.txt

=head1 REQUIREMENTS
Expect module, SSH access to devices, baseline captured before drift detection

=cut

my ($device, $username, $password, $baseline_mode, $help);

GetOptions(
    'device=s'   => \$device,
    'username=s' => \$username,
    'password=s' => \$password,
    'baseline'   => \$baseline_mode,
    'help'       => \$help,
) or die "Error parsing command line arguments\n";

die usage() if $help || !$device;
$username ||= 'admin';

my $baseline_dir = './baselines';
mkdir($baseline_dir) unless -d $baseline_dir;
my $baseline_file = "$baseline_dir/${device}_baseline.txt";
my $logfile = "drift_${device}.log";

open my $LOG, ">>", $logfile or die "Failed to open log file: $!";

sub log_msg {
    my ($msg) = @_;
    my $ts = scalar(localtime());
    print "$msg\n";
    print $LOG "[$ts] $msg\n";
    flush $LOG;
}

sub get_running_config {
    my ($ip, $user, $pass) = @_;
    
    log_msg("[*] Connecting to $ip");
    my $ssh = Expect->new();
    
    unless ($ssh->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 $user\@$ip")) {
        log_msg("[!] Failed to spawn SSH connection");
        return undef;
    }
    
    my $auth_ok = 0;
    eval {
        $ssh->expect(6,
            [ qr/password[:=]\s*$/i, sub { 
                my $self = shift;
                $self->send("$pass\n");
                exp_continue;
            } ],
            [ qr/[>#]\s*$/, sub { $auth_ok = 1; } ],
            [ 'timeout', sub { log_msg("[!] Connection timeout after 6 seconds"); } ],
            [ 'eof', sub { log_msg("[!] SSH connection closed unexpectedly"); } ],
        );
    };
    
    unless ($auth_ok) {
        log_msg("[!] Authentication failed or no prompt received");
        $ssh->hard_close() if defined $ssh;
        return undef;
    }
    
    log_msg("[+] Authenticated, retrieving configuration");
    
    $ssh->send("terminal length 0\n");
    $ssh->expect(2, [ qr/[>#]\s*$/ ]);
    
    $ssh->send("show running-config\n");
    unless ($ssh->expect(20, [ qr/[>#]\s*$/ ])) {
        log_msg("[!] Timeout retrieving running-config");
        $ssh->hard_close();
        return undef;
    }
    
    my $config = $ssh->buffer();
    $ssh->send("exit\n");
    $ssh->hard_close();
    
    return $config if $config && length($config) > 100;
    log_msg("[!] Config retrieval returned invalid data");
    return undef;
}

sub usage {
    print <<'USAGE';
Usage: device_config_drift_detector.pl --device <hostname|ip> [options]

Required:
  --device            Target device hostname or IP address

Options:
  --username          SSH username (default: admin)
  --password          SSH password (prompted if omitted)
  --baseline          Capture and save baseline configuration
  --help              Show this message

Examples:
  ./device_config_drift_detector.pl --device 192.168.1.1 --baseline
  ./device_config_drift_detector.pl --device core-router-01
  cat devices.txt | xargs -I {} ./device_config_drift_detector.pl --device {}

USAGE
    exit 0;
}

unless ($password) {
    print "Enter SSH password for $username\@$device: ";
    system("stty -echo");
    chomp($password = <STDIN>);
    system("stty echo");
    print "\n";
}

my $config = get_running_config($device, $username, $password);

unless ($config) {
    log_msg("[!] Failed to retrieve configuration from $device");
    close $LOG;
    exit 1;
}

if ($baseline_mode) {
    open my $fh, ">", $baseline_file or die "Cannot write baseline file: $!";
    print $fh $config;
    close $fh;
    log_msg("[+] Baseline configuration saved for $device");
} else {
    unless (-f $baseline_file) {
        log_msg("[!] ERROR: No baseline found for $device");
        log_msg("[!] Run with --baseline flag to establish baseline first");
        close $LOG;
        exit 1;
    }
    
    open my $fh, "<", $baseline_file or die "Cannot read baseline file: $!";
    my $baseline = do { local $/; <$fh> };
    close $fh;
    
    if ($config eq $baseline) {
        log_msg("[+] OK: Configuration matches baseline - no drift detected");
    } else {
        log_msg("[!] ALERT: Configuration drift detected on $device");
        
        my @current_lines = split /\n/, $config;
        my @baseline_lines = split /\n/, $baseline;
        my %baseline_hash = map { $_ => 1 } @baseline_lines;
        
        log_msg("--- Changes ---");
        foreach my $line (@current_lines) {
            if ($line && !$baseline_hash{$line}) {
                log_msg("  + $line");
            }
        }
    }
}

close $LOG;
exit 0;