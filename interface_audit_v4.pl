```perl
#!/usr/bin/perl

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::HiRes qw(time);

=head1 NAME

device_stats_collector.pl - Gather system statistics from network devices via SSH

=head1 SYNOPSIS

  device_stats_collector.pl --device 192.168.1.1 --user admin --pass password
  device_stats_collector.pl --file devices.txt --user admin --pass password [--log stats.log]

=head1 DESCRIPTION

Connects to network devices via SSH and collects system statistics including:
device version, uptime, CPU utilization, memory usage, and serial number.
Results are displayed on STDOUT and optionally logged to a file.

=head1 OPTIONS

  --device HOST/IP       Single device hostname or IP
  --file FILENAME        File containing device list (one per line)
  --user USERNAME        SSH username for authentication
  --pass PASSWORD        SSH password for authentication
  --log LOGFILE         Optional log file path for results
  --port PORT           SSH port (default: 22)
  --timeout SECONDS      Command timeout in seconds (default: 15)
  --help                Display this help message

=cut

my ($device, $device_file, $user, $pass, $logfile, $timeout, $port, $help);

GetOptions(
    'device=s'  => \$device,
    'file=s'    => \$device_file,
    'user=s'    => \$user,
    'pass=s'    => \$pass,
    'log=s'     => \$logfile,
    'port=i'    => \$port,
    'timeout=i' => \$timeout,
    'help'      => \$help,
) or die "Error in command line arguments\n";

die_usage() if $help;
die_usage() unless ($device || $device_file) && $user && $pass;

$port    ||= 22;
$timeout ||= 15;

my @devices;
if ($device) {
    push @devices, $device;
} elsif ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^#/ || $line =~ /^\s*$/;
        push @devices, $line;
    }
    close $fh;
}

die "No devices specified\n" unless @devices;

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open $logfile: $!\n";
    print $log_fh "\n=== Collection started at " . scalar(localtime) . " ===\n";
}

my $success_count = 0;
my $fail_count = 0;

foreach my $host (@devices) {
    if (collect_stats($host, $user, $pass, $port, $timeout, $log_fh)) {
        $success_count++;
    } else {
        $fail_count++;
    }
}

if ($logfile) {
    print $log_fh "\n=== Collection completed: $success_count success, $fail_count failures ===\n";
    close $log_fh;
}

print "\nSummary: $success_count succeeded, $fail_count failed\n";
exit($fail_count > 0 ? 1 : 0);

sub collect_stats {
    my ($host, $user, $password, $port, $timeout, $log_fh) = @_;
    
    print "\n[*] Connecting to $host:$port...\n";
    print $log_fh "\n[*] Connecting to $host:$port...\n" if $log_fh;
    
    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host       => $host,
            user       => $user,
            password   => $password,
            port       => $port,
            raw_pty    => 1,
            timeout    => $timeout,
        );
        $ssh->login();
    };
    
    if ($@ || !$ssh) {
        my $err = $@ || "Connection failed";
        print "[-] ERROR connecting to $host: $err\n";
        print $log_fh "[-] ERROR connecting to $host: $err\n" if $log_fh;
        return 0;
    }
    
    print "[+] Connected to $host\n";
    print $log_fh "[+] Connected to $host\n" if $log_fh;
    
    my %stats;
    
    eval {
        $stats{hostname} = $ssh->exec("show run | include hostname") || "Unknown";
        $stats{version} = $ssh->exec("show version | include Cisco IOS|Version") || "Unknown";
        $stats{uptime} = $ssh->exec("show uptime") || "Unknown";
        $stats{cpu} = $ssh->exec("show processes cpu | include CPU utilization") || "Unknown";
        $stats{memory} = $ssh->exec("show memory | include Processor mem") || "Unknown";
        $stats{serial} = $ssh->exec("show version | include Serial") || "Unknown";
    };
    
    if ($@) {
        print "[-] Warning: Some commands failed on $host: $@\n";
        print $log_fh "[-] Warning: Some commands failed on $host: $@\n" if $log_fh;
    }
    
    foreach my $key (sort keys %stats) {
        my $value = $stats{$key};
        next unless defined $value;
        $value =~ s/\n.*//s;
        print "    $key: $value\n";
        print $log_fh "    $key: $value\n" if $log_fh;
    }
    
    eval { $ssh->close(); };
    print "[+] Disconnected from $host\n";
    print $log_fh "[+] Disconnected from $host\n" if $log_fh;
    
    return 1;
}

sub die_usage {
    print <<'USAGE';
Usage: device_stats_collector.pl [options]

Required:
  --user USERNAME        SSH username
  --pass PASSWORD        SSH password
  
One of:
  --device HOST/IP       Single device to query
  --file FILENAME        File with device list

Optional:
  --port PORT           SSH port (default: 22)
  --log LOGFILE         Log file path
  --timeout SECONDS     Command timeout (default: 15)
  --help                Show this message

Examples:
  device_stats_collector.pl --device 10.1.1.1 --user admin --pass secret
  device_stats_collector.pl --file hosts.txt --user admin --pass secret --log results.log
USAGE
    exit 1;
}
```