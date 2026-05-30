```perl
#!/usr/bin/perl
=head1 NAME
device_uptime_collector.pl - Collect device uptime and system resources

=head1 DESCRIPTION
Connects to network devices via SSH and collects uptime, memory, and CPU stats.
Supports single device or bulk collection from file. Outputs to STDOUT and
optional log file for reporting and monitoring.

=head1 USAGE
  device_uptime_collector.pl --host 192.168.1.1 --user admin --pass password
  device_uptime_collector.pl --file devices.txt --user admin --pass password

=head1 PREREQUISITES
  Perl modules: Net::SSH::Expect, Getopt::Long
  SSH access to devices with appropriate privileges
  Device must support 'show version', 'show processes cpu', 'show memory'

=cut

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $password, $logfile, $port, $timeout, $help);

GetOptions(
    'host=s'     => \$host,
    'file=s'     => \$file,
    'user=s'     => \$user,
    'pass=s'     => \$password,
    'log=s'      => \$logfile,
    'port=i'     => \$port,
    'timeout=i'  => \$timeout,
    'help'       => \$help,
) or die "Error in command line arguments\n";

show_help() if $help;
die "Error: --user and --pass required\n" unless $user && $password;
die "Error: Specify --host or --file, not both\n" if ($host && $file) || (!$host && !$file);

$port    //= 22;
$timeout //= 10;

my @devices = $host ? ($host) : read_devices($file);
my $log_fh = $logfile ? open_log($logfile) : undef;

foreach my $device (@devices) {
    next unless $device;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    print "[$ts] Connecting to $device...\n";
    
    my %stats = get_device_stats($device, $user, $password, $port, $timeout);
    
    if ($stats{success}) {
        print_results($device, \%stats, $log_fh);
    } else {
        my $err = "FAILED: $device - $stats{error}";
        print "$err\n";
        print $log_fh "$ts | $err\n" if $log_fh;
    }
}

close $log_fh if $log_fh;
print "\nCollection complete.\n";

sub get_device_stats {
    my ($device, $user, $pass, $port, $timeout) = @_;
    my %stats = (success => 0);
    
    eval {
        my $ssh = Net::SSH::Expect->new(
            host     => $device,
            password => $pass,
            user     => $user,
            port     => $port,
            timeout  => $timeout,
            raw_pty  => 1,
        );
        
        $ssh->login() or die "SSH login failed";
        
        $ssh->send("terminal length 0");
        $ssh->read_till('\\$|#', $timeout);
        
        $ssh->send("show version | include uptime|Uptime");
        $stats{uptime} = $ssh->read_till('\\$|#', $timeout);
        
        $ssh->send("show processes cpu sorted | head -15");
        $stats{cpu} = $ssh->read_till('\\$|#', $timeout);
        
        $ssh->send("show memory | include Processor");
        $stats{memory} = $ssh->read_till('\\$|#', $timeout);
        
        $ssh->close();
        $stats{success} = 1;
    };
    
    if ($@) {
        $stats{success} = 0;
        $stats{error} = $@ || "Unknown error";
    }
    
    return %stats;
}

sub print_results {
    my ($device, $stats, $log_fh) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    
    print "  Device: $device\n";
    print "  Uptime:\n";
    foreach my $line (split /\n/, $stats->{uptime}) {
        print "    $line\n" if $line;
    }
    print "  CPU (Top processes):\n";
    foreach my $line (split /\n/, $stats->{cpu}) {
        print "    $line\n" if $line;
    }
    print "  Memory:\n";
    foreach my $line (split /\n/, $stats->{memory}) {
        print "    $line\n" if $line;
    }
    
    if ($log_fh) {
        print $log_fh "$ts | $device | SUCCESS\n";
    }
}

sub read_devices {
    my ($file) = @_;
    my @devices;
    open my $fh, '<', $file or die "Cannot open $file: $!";
    while (<$fh>) {
        chomp;
        next if /^#|^\s*$/;
        push @devices, $_;
    }
    close $fh;
    return @devices;
}

sub open_log {
    my ($file) = @_;
    open my $fh, '>>', $file or die "Cannot open log $file: $!";
    print $fh "=== Device Stats " . strftime("%Y-%m-%d %H:%M:%S", localtime) . " ===\n";
    return $fh;
}

sub show_help {
    print <<EOF;
Usage: $0 [options]

Options:
  --host <ip>           Connect to single device
  --file <filename>     File with device list (one per line)
  --user <user>         SSH username (required)
  --pass <pass>         SSH password (required)
  --log <file>          Optional log file for results
  --port <num>          SSH port (default: 22)
  --timeout <sec>       Connection timeout seconds (default: 10)
  --help                Show this message

Examples:
  $0 --host 10.1.1.1 --user admin --pass secret
  $0 --file devices.txt --user admin --pass secret --log output.log
EOF
    exit 0;
}
```