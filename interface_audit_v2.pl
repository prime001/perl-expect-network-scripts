#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long;
use Net::SSH::Expect;
use Term::ReadPassword;
use File::Basename;

=head1 device_health_check.pl

Device Health and Connectivity Verification Script

=head1 DESCRIPTION

SSH-based network device health checker that verifies connectivity and 
gathers critical device metrics: uptime, CPU/memory utilization, interface 
status, and device version info. Useful for rapid health assessments across 
device inventory.

=head1 USAGE

  ./device_health_check.pl -h 192.168.1.1 -u admin
  ./device_health_check.pl -f device_list.txt -u netadmin -l health_report.log
  ./device_health_check.pl -h 10.0.0.5 -p mypassword -l report.txt

=head1 PREREQUISITES

- Net::SSH::Expect module (Perl SSH with Expect)
- Perl 5.10 or later
- SSH access to target network devices
- Valid device credentials (username/password)

=head1 OPTIONS

  -h, --host HOST        Target device hostname or IP address
  -f, --file FILE        File containing list of devices (one per line)
  -u, --user USER        SSH username (default: admin)
  -p, --pass PASS        SSH password (prompts interactively if omitted)
  -l, --log FILE         Optional log file for results (appends)
  --timeout SECONDS      SSH connection timeout in seconds (default: 30)
  --help                 Display this help message

=head1 AUTHOR

Network Automation - Device Health Checker

=cut

my %opts = (user => 'admin', timeout => 30);

GetOptions(
    'host|h=s'    => \$opts{host},
    'file|f=s'    => \$opts{file},
    'user|u=s'    => \$opts{user},
    'pass|p=s'    => \$opts{pass},
    'log|l=s'     => \$opts{log},
    'timeout=i'   => \$opts{timeout},
    'help'        => \&usage,
) or die "Error in command line arguments\n";

die "Must specify -h <host> or -f <device_file>\n" unless $opts{host} || $opts{file};

$opts{pass} //= read_password("SSH Password: ");

my @devices = $opts{host} ? ($opts{host}) : read_device_file($opts{file});
die "No devices to check\n" unless @devices;

my $logfh;
if ($opts{log}) {
    open($logfh, '>>', $opts{log}) or warn "Cannot open log file $opts{log}: $!\n";
}

sub log_msg {
    my $msg = shift;
    print $msg;
    print $logfh $msg if $logfh;
}

foreach my $device (@devices) {
    log_msg "\n" . "=" x 65 . "\n";
    log_msg "Device: $device\n";
    log_msg "Timestamp: " . scalar(localtime()) . "\n";
    log_msg "=" x 65 . "\n";

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $opts{user},
        password => $opts{pass},
        timeout  => $opts{timeout},
        raw_pty  => 1,
    );

    my $login_result;
    eval { $login_result = $ssh->login() };
    
    unless ($login_result && !$@) {
        log_msg "[FAIL] SSH connection failed: $@\n";
        next;
    }

    log_msg "[PASS] SSH connection established\n";

    unless ($ssh->waitfor('/[>#$]\s*$/', $opts{timeout})) {
        log_msg "[FAIL] Device prompt not received\n";
        eval { $ssh->close() };
        next;
    }

    check_version($ssh, \%opts);
    check_memory($ssh, \%opts);
    check_interfaces($ssh, \%opts);

    eval { $ssh->close() };
    log_msg "[DONE] Health check completed\n";
}

close($logfh) if $logfh;
log_msg "\nResults logged to: $opts{log}\n" if $opts{log};

sub check_version {
    my ($ssh, $opts) = @_;
    my $output = send_command($ssh, 'show version', $opts->{timeout});
    return unless $output;
    
    if ($output =~ /uptime is\s+(.+?)(?:\n|,|$)/i) {
        log_msg "[INFO] Uptime: $1\n";
    }
}

sub check_memory {
    my ($ssh, $opts) = @_;
    my $output = send_command($ssh, 'show processes memory', $opts->{timeout});
    return unless $output;
    
    if ($output =~ /used\s+(\d+[KMG]?)\s+.*?free\s+(\d+[KMG]?)/i) {
        log_msg "[INFO] Memory - Used: $1, Free: $2\n";
    }
}

sub check_interfaces {
    my ($ssh, $opts) = @_;
    my $output = send_command($ssh, 'show interfaces brief', $opts->{timeout});
    return unless $output;
    
    my $up_count = 0;
    my $down_count = 0;
    my @down_interfaces;
    
    foreach my $line (split /\n/, $output) {
        next unless $line =~ /\S+/;
        if ($line =~ /\s+up\s+/i) {
            $up_count++;
        } elsif ($line =~ /\s+down\s+/i || $line =~ /admin down/i) {
            $down_count++;
            push @down_interfaces, $1 if $line =~ /^(\S+)/;
        }
    }
    
    log_msg "[INFO] Interface Status - Up: $up_count, Down: $down_count\n";
    log_msg "[WARN] Down interface: $_\n" foreach @down_interfaces;
}

sub send_command {
    my ($ssh, $cmd, $timeout) = @_;
    my $output;
    eval {
        $ssh->send($cmd);
        $ssh->waitfor('/[>#$]\s*$/', $timeout);
        $output = $ssh->before();
    };
    return $output if $output && !$@;
    return undef;
}

sub read_device_file {
    my $file = shift;
    open my $fh, '<', $file or die "Cannot open device file $file: $!\n";
    my @devices;
    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^#/ || $line =~ /^\s*$/;
        push @devices, $line;
    }
    close $fh;
    return @devices;
}

sub usage {
    my $prog = basename($0);
    print <<"HELP";
$prog - Network Device Health Checker

Usage: $prog [OPTIONS]

OPTIONS:
  -h, --host HOST        Target device hostname or IP
  -f, --file FILE        File with device list (one per line)
  -u, --user USER        SSH username (default: admin)
  -p, --pass PASSWORD    SSH password (prompts if omitted)
  -l, --log FILE         Log file for results (appends)
  --timeout SECONDS      SSH timeout (default: 30)
  --help                 Show this help message

EXAMPLES:
  $prog -h 192.168.1.100 -u admin
  $prog -f device_inventory.txt -u netadmin -l daily_health.log
  $prog -h switch01.lab -p secretpass -l report.txt --timeout 45

HELP
    exit 0;
}