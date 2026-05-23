```perl
#!/usr/bin/perl
###############################################################################
# Device Health Status Monitor
#
# Purpose:
#   Remotely collects system health metrics from network devices (routers/switches)
#   including CPU, memory, uptime, environmental sensors, and power supply status.
#   Useful for NOC monitoring, troubleshooting, and capacity planning.
#
# Usage:
#   perl device_health_monitor.pl -d <host> -u <user> -p <pass> [-l <logfile>]
#   perl device_health_monitor.pl -d 192.168.1.1 -u netadmin -p MyP@ss -l health.log
#
# Prerequisites:
#   - Net::SSH::Expect module installed
#   - SSH access enabled on target devices
#   - Device credentials provided or in script config
#   - Target device must be a Cisco IOS/IOS-XE router or switch
#
# Author: Network Engineering Team
# Version: 1.0
###############################################################################

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Piece;

my ($device, $username, $password, $logfile, $timeout);
$timeout = 30;

GetOptions(
    'device|d=s'   => \$device,
    'username|u=s' => \$username,
    'password|p=s' => \$password,
    'logfile|l=s'  => \$logfile,
    'timeout|t=i'  => \$timeout,
) or usage();

usage() unless ($device && $username && $password);

my $ssh;
eval {
    $ssh = Net::SSH::Expect->new(
        host => $device,
        password => $password,
        user => $username,
        timeout => $timeout,
        raw_pty => 1
    );
    
    $ssh->connect() or die "SSH connection failed: " . $ssh->error();
};
if ($@) {
    log_output("ERROR: Failed to connect to $device: $@", $logfile);
    exit 1;
}

# Disable pagination for clean output
$ssh->send("terminal length 0");
$ssh->waitfor('>', 5);

my %metrics = ();
my @commands = (
    ['show version | include (Device ID|uptime)', 'Device Information'],
    ['show processes cpu sorted | head 20', 'Top CPU Consumers'],
    ['show memory statistics | include Processor', 'Memory Utilization'],
    ['show environment all', 'Environmental Status'],
    ['show power supply', 'Power Supply Status'],
);

foreach my $cmd (@commands) {
    my ($command, $label) = @$cmd;
    eval {
        my $output = $ssh->send($command);
        $metrics{$label} = $output;
    };
    if ($@) {
        log_output("WARNING: Command '$command' failed: $@", $logfile);
        $metrics{$label} = "Command execution failed";
    }
}

$ssh->send("exit");
$ssh->close();

# Format and output report
my $timestamp = localtime->strftime('%Y-%m-%d %H:%M:%S');
my $report = "";
$report .= "=" x 70 . "\n";
$report .= "Device Health Status Report\n";
$report .= "=" x 70 . "\n";
$report .= "Device: $device\n";
$report .= "Timestamp: $timestamp\n";
$report .= "=" x 70 . "\n\n";

foreach my $label (keys %metrics) {
    $report .= "--- $label ---\n";
    $report .= $metrics{$label} . "\n\n";
}

$report .= "=" x 70 . "\n";

print $report;
log_output($report, $logfile) if $logfile;
exit 0;

###############################################################################
sub log_output {
    my ($message, $file) = @_;
    return unless $file;
    
    open my $fh, '>>', $file or warn "Cannot open logfile $file: $!\n";
    print $fh $message . "\n" if $fh;
    close $fh if $fh;
}

sub usage {
    print << 'EOF';
Device Health Status Monitor - Collects CPU, memory, environmental metrics

Usage: perl device_health_monitor.pl [options]

Required Options:
  -d, --device <host>      Target device hostname or IP address
  -u, --username <user>    SSH username for authentication
  -p, --password <pass>    SSH password for authentication

Optional Options:
  -l, --logfile <path>     Append results to logfile (default: stdout only)
  -t, --timeout <sec>      SSH timeout in seconds (default: 30)
  -h, --help               Display this help message

Examples:
  perl device_health_monitor.pl -d 192.168.1.1 -u admin -p MyPass123
  perl device_health_monitor.pl -d router1.example.com -u netadmin -p Secret -l /var/log/health.log

EOF
    exit 1;
}
```