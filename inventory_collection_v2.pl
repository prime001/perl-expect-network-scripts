```perl
#!/usr/bin/perl
=pod
device_health_check.pl - Network device CPU, memory, and temperature monitoring

PURPOSE:
  Remotely connects to network devices via SSH and collects health metrics
  (CPU utilization, memory usage, temperature). Useful for operational
  monitoring and capacity planning. Logs all results and alerts on thresholds.

USAGE:
  perl device_health_check.pl <device_ip> <username> <password> [--log <logfile>]

EXAMPLES:
  perl device_health_check.pl 192.168.1.1 admin password123
  perl device_health_check.pl router1.example.com netadmin pass456 --log health.log

PREREQUISITES:
  - Expect Perl module (install via: cpan install Expect)
  - SSH access to devices with password authentication
  - Supported platforms: Cisco IOS, IOS-XE, ASA, Juniper, Arista
  - Device commands: show processes cpu, show memory, show environment

ERROR HANDLING:
  - SSH connection failures cause immediate exit with logging
  - Authentication failures are caught and reported
  - Command timeouts default to N/A values
  - All events logged to STDOUT and logfile with timestamps
  - Thresholds trigger alerts: CPU 80%, Memory 85%, Temp 70°C

=cut

use strict;
use warnings;
use Expect;
use Getopt::Long;
use Time::localtime;

my $logfile;
GetOptions('log=s' => \$logfile) or die "Error parsing options\n";

my ($device, $user, $pass) = @ARGV;
die "Usage: $0 <device_ip> <username> <password> [--log logfile]\n" 
    unless $device && $user && $pass;

$logfile ||= sprintf("health_check_%s_%d.log", $device, time());
open my $LOG, '>>', $logfile or die "Cannot open logfile: $!\n";

sub log_entry {
    my ($msg) = @_;
    my $timestamp = scalar localtime;
    print "$timestamp | $msg\n";
    print $LOG "$timestamp | $msg\n";
    $LOG->flush();
}

log_entry("Device health check initiated for $device");

my $exp = Expect->new();
$exp->log_stdout(0);
$exp->timeout(10);

eval {
    log_entry("Establishing SSH connection to $device...");
    $exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 $user\@$device")
        or die "SSH spawn failed: $!";
    
    $exp->expect(10, ['password:', sub { $exp->send("$pass\n"); exp_continue; }],
                      ['Permission denied', sub { die "Authentication failed\n"; }],
                      ['#', sub {}],
                      ['>', sub {}]);
    
    log_entry("Connection and authentication successful");
} or do {
    log_entry("CRITICAL: Connection failed - $@");
    close $LOG;
    exit 1;
};

my %metrics;

eval {
    log_entry("Collecting CPU utilization...");
    $exp->send("show processes cpu | include CPU\n");
    $exp->expect(8, qr/#|>/);
    if ($exp->before() =~ /(\d+)%/) {
        $metrics{cpu} = $1;
        log_entry("CPU utilization: $metrics{cpu}%");
    }
};

eval {
    log_entry("Collecting memory statistics...");
    $exp->send("show memory | include Processor\n");
    $exp->expect(8, qr/#|>/);
    if ($exp->before() =~ /(\d+)\s+bytes\s+total.*?(\d+)\s+bytes\s+free/s) {
        my $used_pct = int(100 * ($1 - $2) / $1);
        $metrics{mem} = $used_pct;
        log_entry("Memory usage: $metrics{mem}%");
    }
};

eval {
    log_entry("Collecting temperature readings...");
    $exp->send("show environment | include -i temperature\n");
    $exp->expect(8, qr/#|>/);
    if ($exp->before() =~ /(\d+)\s*°?C/) {
        $metrics{temp} = $1;
        log_entry("System temperature: $metrics{temp}°C");
    }
};

$exp->send("exit\n");
$exp->soft_close();

log_entry("=== HEALTH CHECK RESULTS ===");
log_entry(sprintf("Device: %s", $device));
log_entry(sprintf("CPU Utilization: %s%%", $metrics{cpu} // "N/A"));
log_entry(sprintf("Memory Usage: %s%%", $metrics{mem} // "N/A"));
log_entry(sprintf("Temperature: %s°C", $metrics{temp} // "N/A"));

if ($metrics{cpu} && $metrics{cpu} > 80) {
    log_entry("ALERT: High CPU utilization detected");
}
if ($metrics{mem} && $metrics{mem} > 85) {
    log_entry("ALERT: High memory usage detected");
}
if ($metrics{temp} && $metrics{temp} > 70) {
    log_entry("ALERT: Elevated temperature detected");
}

log_entry("Health check completed successfully");
close $LOG;
exit 0;
```