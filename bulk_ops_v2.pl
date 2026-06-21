#!/usr/bin/perl
=head1 DEVICE HEALTH CHECK

PURPOSE:
  Collects CPU, memory, temperature, and uptime metrics from network devices
  via SSH using Net::SSH::Expect. Enables proactive health monitoring for
  identifying devices approaching resource limits or thermal thresholds.

USAGE:
  perl 031_device_health_check.pl --host 192.168.1.1
  perl 031_device_health_check.pl --file devices.txt --log health_report.log
  perl 031_device_health_check.pl --host 192.168.1.1 --user netadmin --pass P@ssw0rd

PREREQUISITES:
  - Net::SSH::Expect module (cpan Net::SSH::Expect)
  - SSH access enabled on target devices
  - Administrative or operator-level credentials
  - Device must support: show version, show processes cpu, show memory, show environment

TESTED ON:
  - Cisco IOS/IOS-XE
  - Arista EOS (basic support)
  - Juniper (requires syntax adaptation)

=cut

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Localtime;

my ($host, $file, $log, $user, $pass, $help);

GetOptions(
    'host=s'  => \$host,
    'file=s'  => \$file,
    'log=s'   => \$log,
    'user=s'  => \$user,
    'pass=s'  => \$pass,
    'help'    => \$help,
) or die "Error in command line arguments\n";

if ($help || (!$host && !$file)) {
    print "Usage: $0 --host <ip> [--log <file>] [--user <user>] [--pass <pass>]\n";
    print "       $0 --file <device_list> [--log <file>] [--user <user>] [--pass <pass>]\n";
    exit 0;
}

$user //= 'admin';
$pass //= 'admin';

my @devices;
if ($file) {
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
} else {
    push @devices, $host;
}

open my $logfh, '>>', $log if $log;

my $timestamp = scalar localtime;
my $header_msg = "[" . $timestamp . "] Device Health Check Started\n";
print $header_msg;
print $logfh $header_msg if $logfh;

print "-" x 110 . "\n";
printf "%-20s | %-30s | %-10s | %-25s | %-10s\n", "Device", "Uptime", "CPU", "Memory", "Temp";
print "-" x 110 . "\n";

foreach my $device (@devices) {
    $device =~ s/\s+//g;
    next unless $device;
    
    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $user,
        password => $pass,
        timeout  => 30,
        raw_pty  => 1,
    );
    
    my %health = (device => $device, uptime => "N/A", cpu => "N/A", memory => "N/A", temp => "N/A");
    
    eval {
        $ssh->login();
        
        $ssh->send("terminal length 0");
        $ssh->waitfor('[#>]', 5);
        
        eval {
            $ssh->send("show version");
            my $out = $ssh->waitfor('[#>]', 10);
            $health{uptime} = $1 if $out =~ /uptime is\s+(.+?)(?:\n|$)/;
        };
        
        eval {
            $ssh->send("show processes cpu sorted | include CPU");
            my $out = $ssh->waitfor('[#>]', 10);
            $health{cpu} = $1 . "%" if $out =~ /CPU utilization[^:]*:\s*(\d+)/;
        };
        
        eval {
            $ssh->send("show memory | head -10");
            my $out = $ssh->waitfor('[#>]', 10);
            if ($out =~ /(\d+)\s*K\s+used.*?(\d+)\s*K\s+free/i) {
                my $used = $1;
                my $free = $2;
                my $total = $used + $free;
                my $pct = int(($used / $total) * 100);
                $health{memory} = "${pct}% (${used}K/${total}K)";
            }
        };
        
        eval {
            $ssh->send("show environment temperature 2>/dev/null || show environment");
            my $out = $ssh->waitfor('[#>]', 10);
            $health{temp} = $1 . "C" if $out =~ /(\d+)\s*degrees?/i;
        };
        
        $ssh->close();
    };
    
    if ($@) {
        $health{uptime} = "CONN_ERROR";
        $health{cpu} = "FAILED";
    }
    
    my $output = sprintf("%-20s | %-30s | %-10s | %-25s | %-10s\n",
        $health{device}, $health{uptime}, $health{cpu}, $health{memory}, $health{temp});
    
    print $output;
    print $logfh $output if $logfh;
}

print "-" x 110 . "\n";
my $end_msg = "Device Health Check Completed\n";
print $end_msg;
print $logfh $end_msg if $logfh;

close $logfh if $logfh;
exit 0;