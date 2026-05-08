#!/usr/bin/perl
# Device Health Monitor - SSH Expect script for network device health monitoring
#
# Purpose: Monitor and report device health metrics (CPU, memory, system processes)
#          from network devices via SSH. Detects performance degradation before issues
#          escalate. Useful for proactive NOC monitoring.
#
# Usage:   perl 041_device_health_monitor.pl <device_ip> [username] [password] [logfile]
#          perl 041_device_health_monitor.pl devices.txt admin MyPass health.log
#
# Prerequisites:
#  - Perl modules: Expect, strict, warnings
#  - SSH access to devices (keys or password authentication)
#  - Devices support 'show processes cpu' and 'show memory' commands
#  - Can read device list from file (one IP/hostname per line)
#
# Output:
#  - STDOUT: Formatted health status with threshold indicators (OK/WARNING/CRITICAL)
#  - Log file: Timestamped results appended to file if specified
#  - Exit code: 0 on success, non-zero on errors

use strict;
use warnings;
use Expect;
use Time::Localtime;
use Fcntl;

my ($device, $user, $pass, $logfile) = @ARGV;
die "Usage: $0 <device_ip|file> [username] [password] [logfile]\n" unless $device;

$user ||= $ENV{NET_USER} || 'admin';
$pass ||= $ENV{NET_PASS} || 'admin';

sub log_msg {
    my ($msg) = @_;
    print $msg;
    return unless $logfile && open(my $fh, '>>', $logfile);
    print $fh scalar(localtime()) . " - $msg";
    close($fh);
}

sub get_devices {
    my ($input) = @_;
    return (-f $input) ? do {
        open(my $fh, '<', $input) or die "Cannot read $input: $!\n";
        my @list = grep { chomp; $_ } <$fh>;
        close($fh);
        @list;
    } : ($input);
}

sub check_device_health {
    my ($dev_ip) = @_;
    log_msg("\n" . "=" x 55 . "\n");
    log_msg("Device: $dev_ip at " . scalar(localtime()) . "\n");
    log_msg("=" x 55 . "\n");

    my $exp = Expect->new();
    $exp->log_stdout(0);
    $exp->timeout(12);

    unless ($exp->spawn("ssh", "-o", "StrictHostKeyChecking=no", "$user\@$dev_ip")) {
        log_msg("ERROR: Cannot spawn SSH to $dev_ip: $!\n");
        return 0;
    }

    my $authenticated = 0;
    $exp->expect(
        12,
        ['password:', sub { $exp->send("$pass\n"); exp_continue; }],
        ['yes/no', sub { $exp->send("yes\n"); exp_continue; }],
        [qr/[#>]\s*$/, sub { $authenticated = 1; }],
    );

    unless ($authenticated) {
        log_msg("ERROR: Authentication failed\n");
        $exp->hard_close();
        return 0;
    }

    $exp->send("terminal length 0\n");
    $exp->expect(2, qr/[#>]\s*$/);

    my %metrics = ();

    # Get CPU utilization
    $exp->send("show processes cpu\n");
    my $cpu_output = '';
    eval {
        $exp->expect(6, sub { $cpu_output = $exp->before(); });
    };
    $exp->expect(1, qr/[#>]\s*$/);

    if ($cpu_output =~ /CPU\s+utilization.*?(\d+)%/i) {
        $metrics{cpu} = $1;
    } elsif ($cpu_output =~ /(\d+)%\s+Busy/i) {
        $metrics{cpu} = $1;
    }

    # Get memory status
    $exp->send("show memory\n");
    my $mem_output = '';
    eval {
        $exp->expect(6, sub { $mem_output = $exp->before(); });
    };
    $exp->expect(1, qr/[#>]\s*$/);

    if ($mem_output =~ /Processor.*?(\d+)\s+free/i) {
        $metrics{mem_free} = int($1 / 1024);
    }

    $exp->send("exit\n");
    $exp->expect(2);
    $exp->hard_close();

    # Report results with thresholds
    log_msg("\nHealth Metrics:\n");

    if (defined $metrics{cpu}) {
        my $status = $metrics{cpu} > 85 ? "CRITICAL" : 
                     $metrics{cpu} > 70 ? "WARNING" : "OK";
        log_msg(sprintf("  CPU Utilization: %d%% [%s]\n", $metrics{cpu}, $status));
    } else {
        log_msg("  CPU Utilization: Unable to retrieve\n");
    }

    if (defined $metrics{mem_free}) {
        log_msg(sprintf("  Memory Available: %d MB\n", $metrics{mem_free}));
    }

    log_msg("\nStatus: Health check completed successfully\n");
    return 1;
}

my @devices = get_devices($device);
my $success_count = 0;

foreach my $dev (grep { $_ } @devices) {
    $success_count++ if check_device_health($dev);
}

log_msg("\nSummary: Monitored " . scalar(@devices) . 
        " device(s), " . $success_count . " successful\n");

exit($success_count == @devices ? 0 : 1);