#!/usr/bin/perl
use strict;
use warnings;

=head1 NAME
device_health_monitor.pl - Monitor network device environmental and system health

=head1 DESCRIPTION
Connects to network devices via SSH and collects critical health metrics:
- Device uptime and system information
- Environmental sensors (temperature, power supplies, fans)
- CPU and memory utilization
- Overall device health status

Outputs results to STDOUT and optional log file for trend analysis and alerting.

=head1 USAGE
./device_health_monitor.pl <device_ip> [logfile]
./device_health_monitor.pl -f devices.txt [logfile]

=head1 PREREQUISITES
Net::SSH::Expect module, SSH access to devices with credentials in environment vars:
NETWORK_USER and NETWORK_PASS, or prompted interactively.

=cut

use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);
use Fcntl qw(:flock);

my ($device_file, $logfile);
GetOptions('f|file=s' => \$device_file, 'l|log=s' => \$logfile) or die "Error in options\n";

my @devices;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    @devices = grep { chomp; $_ && !/^#/ } <$fh>;
    close $fh;
} elsif (@ARGV) {
    $devices[0] = $ARGV[0];
    $logfile = $ARGV[1] if $ARGV[1];
} else {
    die "Usage: $0 <device> [logfile] OR $0 -f file.txt [logfile]\n";
}

die "No devices to monitor\n" unless @devices;

my $user = $ENV{NETWORK_USER} || 'admin';
my $pass = $ENV{NETWORK_PASS} || prompt_password("SSH Password: ");

foreach my $device (@devices) {
    chomp $device;
    next if !$device || $device =~ /^\s*#/;
    
    my $health = check_device_health($device, $user, $pass);
    print_health_report($health, $logfile);
}

sub check_device_health {
    my ($host, $user, $pass) = @_;
    my %health = (
        host      => $host,
        timestamp => strftime('%Y-%m-%d %H:%M:%S', localtime),
        status    => 'UNKNOWN',
    );
    
    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host    => $host,
            user    => $user,
            password => $pass,
            timeout => 25,
            raw_pty => 1,
        );
        $ssh->login() or die "Login failed\n";
        
        $health{status} = 'OK';
        $health{uptime} = extract_value($ssh->exec("show version"), 'uptime|System.*uptime', 1);
        $health{model} = extract_value($ssh->exec("show version"), 'Model|Device ID', 1);
        
        my $env = $ssh->exec("show environment all") || $ssh->exec("show environment");
        $health{temperature} = extract_value($env, 'temp|Ambient', 0);
        $health{psu} = extract_value($env, 'Power.*?Status|PSU', 0);
        $health{fan} = extract_value($env, 'Fan.*?Status', 0);
        
        my $mem = $ssh->exec("show memory") || $ssh->exec("show processes memory");
        if ($mem =~ /(\d+)\s*%.*?[Uu]sed/) {
            $health{memory_used} = $1 . '%';
        }
        
        my $cpu = $ssh->exec("show processes cpu") || $ssh->exec("show cpu");
        if ($cpu =~ /(\d+(?:\.\d+)?)\s*%/) {
            $health{cpu_usage} = $1 . '%';
        }
        
        $ssh->close();
    };
    
    if ($@) {
        $health{status} = 'FAILED';
        $health{error} = $@;
    }
    
    return \%health;
}

sub extract_value {
    my ($output, $pattern, $is_uptime) = @_;
    return 'N/A' unless $output;
    
    foreach my $line (split /\n/, $output) {
        if ($line =~ /$pattern/i) {
            if ($is_uptime) {
                return $line if $line =~ /\d+\s*(day|hour|min|year)/i;
            } else {
                if ($line =~ /:\s*(.+?)$/) {
                    return $1;
                } elsif ($line =~ /($pattern.*)/i) {
                    return $1;
                }
            }
        }
    }
    return 'N/A';
}

sub print_health_report {
    my ($health, $logfile) = @_;
    
    my $report = "\n" . ('='x75) . "\n";
    $report .= "DEVICE HEALTH REPORT\n";
    $report .= "="x75 . "\n";
    $report .= sprintf("Host: %-30s | Time: %s\n", $health->{host}, $health->{timestamp});
    $report .= sprintf("Status: %-50s\n\n", $health->{status});
    
    if ($health->{status} eq 'OK') {
        $report .= "System Information:\n";
        $report .= sprintf("  Uptime........: %s\n", $health->{uptime});
        $report .= sprintf("  Model..........: %s\n", $health->{model});
        
        $report .= "\nHealth Metrics:\n";
        $report .= sprintf("  CPU Usage......: %s\n", $health->{cpu_usage} || 'N/A');
        $report .= sprintf("  Memory Used....: %s\n", $health->{memory_used} || 'N/A');
        $report .= sprintf("  Temperature....: %s\n", $health->{temperature});
        $report .= sprintf("  PSU Status.....: %s\n", $health->{psu});
        $report .= sprintf("  Fan Status.....: %s\n", $health->{fan});
    } else {
        $report .= "ERROR: " . ($health->{error} || 'Unknown error') . "\n";
    }
    
    $report .= ('='x75) . "\n";
    
    print $report;
    
    if ($logfile) {
        open my $fh, '>>', $logfile or warn "Cannot open log: $!\n";
        flock($fh, LOCK_EX) if defined fileno($fh);
        print $fh $report;
        flock($fh, LOCK_UN) if defined fileno($fh);
        close $fh;
    }
}

sub prompt_password {
    my ($prompt) = @_;
    print $prompt;
    system("stty -echo 2>/dev/null");
    my $pwd = <STDIN>;
    system("stty echo 2>/dev/null");
    print "\n";
    chomp $pwd;
    return $pwd;
}

1;