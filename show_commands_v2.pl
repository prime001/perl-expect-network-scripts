```perl
#!/usr/bin/perl
# =============================================================================
# cpu_mem_check.pl - Network Device CPU & Memory Health Monitor
# =============================================================================
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE devices via SSH and retrieves
#   CPU utilization and memory usage. Useful for capacity planning, on-call
#   triage, and scheduled health checks. Flags readings that exceed thresholds.
#
# Usage:
#   Single device:  perl cpu_mem_check.pl -h 192.168.1.1 -u admin -p pass
#   Device file:    perl cpu_mem_check.pl -f devices.txt -u admin -p pass
#   With log:       perl cpu_mem_check.pl -h 192.168.1.1 -u admin -p pass -l report.log
#   Thresholds:     perl cpu_mem_check.pl -h 192.168.1.1 -u admin -p pass -c 70 -m 80
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH access enabled on target devices
#   Devices file: one IP/hostname per line; blank lines and # comments ignored
#
# Options:
#   -h <host>    Target device IP or hostname
#   -f <file>    File containing list of device IPs/hostnames
#   -u <user>    SSH username
#   -p <pass>    SSH password
#   -e <pass>    Enable password (optional)
#   -l <file>    Log file path (optional, appended)
#   -c <pct>     CPU alert threshold % (default: 80)
#   -m <pct>     Memory alert threshold % (default: 85)
#   -t <sec>     SSH timeout seconds (default: 30)
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);

our %opts;
getopts('h:f:u:p:e:l:c:m:t:', \%opts);

my $user       = $opts{u} or die "Usage: $0 -h <host>|-f <file> -u <user> -p <pass> [options]\n";
my $pass       = $opts{p} or die "SSH password required (-p)\n";
my $enable     = $opts{e} // '';
my $logfile    = $opts{l} // '';
my $cpu_thresh = $opts{c} // 80;
my $mem_thresh = $opts{m} // 85;
my $timeout    = $opts{t} // 30;

my @devices;
if ($opts{h}) {
    push @devices, $opts{h};
} elsif ($opts{f}) {
    open(my $fh, '<', $opts{f}) or die "Cannot open device file '$opts{f}': $!\n";
    while (<$fh>) { chomp; next if /^\s*$/ || /^\s*#/; push @devices, $_; }
    close $fh;
} else {
    die "Specify a target host (-h) or device file (-f)\n";
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log '$logfile': $!\n";
}

sub emit {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
emit("=" x 62 . "\n");
emit("CPU & Memory Health Check  |  $ts\n");
emit("Thresholds: CPU>=${cpu_thresh}%  Memory>=${mem_thresh}%\n");
emit("=" x 62 . "\n\n");

for my $host (@devices) {
    emit("[$host]\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $user,
        password => $pass,
        raw_pty  => 1,
        timeout  => $timeout,
    );

    my $connected;
    eval { $connected = $ssh->login() };
    if ($@ || !defined $connected || $connected =~ /[Pp]assword/) {
        emit("  ERROR: Cannot connect or authenticate - $@\n\n");
        next;
    }

    if ($enable) {
        $ssh->send("enable");
        if ($ssh->waitfor('Password:', $timeout)) {
            $ssh->send($enable);
            $ssh->waitfor('[#>]', $timeout);
        }
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('[#>]', $timeout);

    $ssh->send("show processes cpu | include CPU utilization");
    my $cpu_out = $ssh->waitfor('[#>]', $timeout) // '';

    my ($cpu_5s, $cpu_1m, $cpu_5m) = ('?', '?', '?');
    if ($cpu_out =~ /CPU utilization[^:]*:\s*(\d+)%\/(\d+)%;\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%/) {
        ($cpu_5s, $cpu_1m, $cpu_5m) = ($1, $3, $4);
    } elsif ($cpu_out =~ /(\d+)%.*?(\d+)%.*?(\d+)%/) {
        ($cpu_5s, $cpu_1m, $cpu_5m) = ($1, $2, $3);
    }

    $ssh->send("show processes memory | include Processor");
    my $mem_out = $ssh->waitfor('[#>]', $timeout) // '';

    my ($mem_used, $mem_free, $mem_pct) = ('?', '?', '?');
    if ($mem_out =~ /Processor\s+(\d+)\s+(\d+)\s+(\d+)/i) {
        my ($total, $used, $free) = ($1, $2, $3);
        $mem_used = $used;
        $mem_free = $free;
        $mem_pct  = int(($used / $total) * 100) if $total > 0;
    }

    $ssh->send("exit");
    eval { $ssh->close() };

    my $cpu_tag = ($cpu_1m ne '?' && $cpu_1m >= $cpu_thresh) ? " *** ALERT ***" : "";
    my $mem_tag = ($mem_pct ne '?' && $mem_pct >= $mem_thresh) ? " *** ALERT ***" : "";

    emit(sprintf("  CPU  5s=%-3s%% 1m=%-3s%% 5m=%-3s%%%s\n", $cpu_5s, $cpu_1m, $cpu_5m, $cpu_tag));
    emit(sprintf("  Mem  used=%-10s free=%-10s util=%s%%%s\n", $mem_used, $mem_free, $mem_pct, $mem_tag));
    emit("\n");
}

emit("Done. " . scalar(@devices) . " device(s) checked.\n");
emit("Log: $logfile\n") if $logfile;
close $log_fh if $log_fh;
```