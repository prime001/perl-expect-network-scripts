```perl
#!/usr/bin/perl
=pod
=head1 NAME

device_health_monitor.pl - Network Device System Health Monitoring Tool

=head1 DESCRIPTION

Connects to network devices via SSH and collects real-time system health metrics
including CPU utilization, memory usage, uptime, and temperature. Supports both
Cisco IOS and NX-OS platforms. Generates health status reports with alerting
for critical thresholds.

=head1 USAGE

./device_health_monitor.pl [--device IP] [--file device_list.txt] [--log output.log]

Examples:
  ./device_health_monitor.pl --device 10.0.0.1
  ./device_health_monitor.pl --file devices.txt --log health.log

=head1 PREREQUISITES

Perl modules: Net::SSH::Expect
SSH access to devices with appropriate credentials
Devices must support: show processes cpu, show memory, show version, show env

=head1 NOTES

Uses environment variables DEVICE_USER and DEVICE_PASS for credentials.
Defaults to admin/password if not set.

=cut

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Localtime;

my ($device, $file, $logfile, $help);
GetOptions(
    'device=s' => \$device,
    'file=s'   => \$file,
    'log=s'    => \$logfile,
    'help|h'   => \$help,
) or die "Error in command line arguments\n";

die usage() if $help || (!$device && !$file);

my @devices;
if ($device) {
    push @devices, $device;
} elsif ($file) {
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    @devices = grep { chomp; $_ && !/^\s*#/ } <$fh>;
    close $fh;
}

my $timestamp = scalar(localtime);
my $report = "\n" . "="x70 . "\n";
$report .= "Device Health Monitoring Report - $timestamp\n";
$report .= "="x70 . "\n\n";

my $critical_count = 0;

foreach my $dev (@devices) {
    $dev =~ s/^\s+|\s+$//g;
    next unless $dev;
    
    print "[$dev] Collecting health metrics... ";
    my %health = collect_health($dev);
    
    if ($health{error}) {
        print "ERROR\n";
        $report .= "DEVICE: $dev\n";
        $report .= "  STATUS: CONNECTION FAILED\n";
        $report .= "  ERROR: $health{error}\n\n";
        $critical_count++;
        next;
    }
    
    print "OK\n";
    
    $report .= "DEVICE: $dev\n";
    $report .= "  Hostname: $health{hostname}\n";
    $report .= "  Uptime: $health{uptime}\n";
    $report .= "  CPU 5-sec: $health{cpu_5sec}% ";
    $report .= $health{cpu_5sec} > 80 ? "[CRITICAL]" : "";
    $report .= "\n";
    $report .= "  Memory Used: $health{memory_used}MB / $health{memory_total}MB ";
    my $mem_pct = int(($health{memory_used} / $health{memory_total}) * 100);
    $report .= "($mem_pct%) ";
    $report .= $mem_pct > 85 ? "[WARNING]" : "";
    $report .= "\n";
    
    if ($health{temperature}) {
        $report .= "  Temperature: $health{temperature}C ";
        $report .= $health{temperature} > 60 ? "[WARNING]" : "";
        $report .= "\n";
    }
    
    my $health_status = "HEALTHY";
    $health_status = "WARNING" if ($health{cpu_5sec} > 70 || $mem_pct > 75);
    $health_status = "CRITICAL" if ($health{cpu_5sec} > 85 || $mem_pct > 90);
    
    $report .= "  OVERALL STATUS: $health_status\n\n";
    $critical_count++ if $health_status eq "CRITICAL";
}

$report .= "="x70 . "\n";
$report .= "Summary: " . scalar(@devices) . " device(s) monitored, ";
$report .= "$critical_count critical\n";

print $report;

if ($logfile) {
    open my $fh, '>', $logfile or die "Cannot write to $logfile: $!\n";
    print $fh $report;
    close $fh;
    print "\nReport saved to $logfile\n";
}

sub collect_health {
    my ($host) = @_;
    my %health = (
        hostname     => "",
        uptime       => "",
        cpu_5sec     => 0,
        memory_used  => 0,
        memory_total => 0,
        temperature  => 0,
    );
    
    my $user = $ENV{DEVICE_USER} || 'admin';
    my $pass = $ENV{DEVICE_PASS} || 'password';
    
    my $ssh = Net::SSH::Expect->new(
        host    => $host,
        user    => $user,
        password => $pass,
        timeout => 15,
        raw_pty => 1,
    );
    
    eval {
        my $login = $ssh->login();
        die "Login failed" if !$login || $login =~ /error|failed|denied/i;
        
        $ssh->send("terminal length 0");
        $ssh->waitfor('>', 2);
        
        # Get hostname and uptime
        $ssh->send("show version | include uptime|System uptime");
        my $version = $ssh->read_till('>', 3);
        ($health{uptime}) = $version =~ /uptime is (.+)/i;
        
        # Get CPU
        $ssh->send("show processes cpu | include CPU|utilization");
        my $cpu_out = $ssh->read_till('>', 3);
        ($health{cpu_5sec}) = $cpu_out =~ /5\s+sec:\s+(\d+)%/i;
        
        # Get memory
        $ssh->send("show memory | include Memory");
        my $mem_out = $ssh->read_till('>', 3);
        if ($mem_out =~ /(\d+)\s+bytes\s+total\s+\((.+?)\).+?(\d+)\s+bytes\s+free/i) {
            $health{memory_total} = int($1 / (1024*1024));
            $health{memory_used} = $health{memory_total} - int($3 / (1024*1024));
        }
        
        # Get temperature (if available)
        $ssh->send("show env temperature | include Temp");
        my $temp_out = $ssh->read_till('>', 3);
        ($health{temperature}) = $temp_out =~ /(\d+)\s*°?C/i;
        
        $ssh->close();
    };
    
    if ($@) {
        $health{error} = $@;
    }
    
    return %health;
}

sub usage {
    return <<'EOF';
Usage: device_health_monitor.pl [OPTIONS]

OPTIONS:
  --device IP          Target device IP or hostname
  --file FILE          File containing device list (one per line)
  --log FILE           Save report to file
  --help               Display this help message

ENVIRONMENT VARIABLES:
  DEVICE_USER          SSH username (default: admin)
  DEVICE_PASS          SSH password (default: password)

EXAMPLES:
  ./device_health_monitor.pl --device 192.168.1.1
  ./device_health_monitor.pl --file devices.txt --log report.txt

THRESHOLDS:
  CPU Warning:  > 70%  |  Critical: > 85%
  Memory Warning: > 75%  |  Critical: > 90%
  Temperature Warning: > 60C

EOF
}
```