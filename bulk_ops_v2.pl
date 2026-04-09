```perl
#!/usr/bin/perl
# =============================================================================
# cpu_memory_health.pl - Network Device CPU/Memory Health Check
# =============================================================================
# Purpose:
#   Polls CPU utilization and memory usage across one or more Cisco IOS/IOS-XE
#   devices via SSH. Flags devices exceeding configurable thresholds. Useful
#   for NOC health sweeps, pre/post-change baseline captures, and incident triage.
#
# Usage:
#   Single device:   ./cpu_memory_health.pl -h 192.168.1.1 -u admin -p secret
#   Device list:     ./cpu_memory_health.pl -f devices.txt -u admin -p secret
#   With log file:   ./cpu_memory_health.pl -f devices.txt -u admin -p secret -l health.log
#   Custom thresh:   ./cpu_memory_health.pl -h 10.0.0.1 -u admin -p secret --cpu 70 --mem 85
#
# Prerequisites:
#   cpan install Net::SSH::Expect Getopt::Long
#
# Device file format: one IP/hostname per line, blank lines and # comments ok
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log);
my $cpu_thresh = 80;
my $mem_thresh = 90;
my $timeout    = 15;

GetOptions(
    'h|host=s'     => \$opt_host,
    'f|file=s'     => \$opt_file,
    'u|user=s'     => \$opt_user,
    'p|pass=s'     => \$opt_pass,
    'l|log=s'      => \$opt_log,
    'cpu=i'        => \$cpu_thresh,
    'mem=i'        => \$mem_thresh,
) or die "Usage: $0 -h HOST | -f FILE -u USER -p PASS [-l LOGFILE] [--cpu N] [--mem N]\n";

die "Specify -h HOST or -f FILE\n"    unless $opt_host || $opt_file;
die "Username required (-u)\n"        unless $opt_user;
die "Password required (-p)\n"        unless $opt_pass;

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open(my $fh, '<', $opt_file) or die "Cannot open $opt_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*$/ || /^\s*#/; push @devices, $_; }
    close $fh;
}

my $log_fh;
if ($opt_log) {
    open($log_fh, '>>', $opt_log) or die "Cannot open log $opt_log: $!\n";
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
output("=" x 70);
output("CPU/Memory Health Check  |  $ts");
output(sprintf("Thresholds: CPU >%d%%  Memory >%d%%", $cpu_thresh, $mem_thresh));
output("=" x 70);

my ($ok_count, $warn_count, $err_count) = (0, 0, 0);

for my $device (@devices) {
    my $result = check_device($device);
    if    ($result->{status} eq 'ERROR') { $err_count++ }
    elsif ($result->{status} eq 'WARN')  { $warn_count++ }
    else                                  { $ok_count++ }
}

output("-" x 70);
output(sprintf("Summary: %d OK  %d WARN  %d ERROR  (%d devices)",
    $ok_count, $warn_count, $err_count, scalar @devices));
close $log_fh if $log_fh;

# ------------------------------------------------------------------ #

sub check_device {
    my ($host) = @_;
    my %result = (host => $host, status => 'OK');

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $opt_user,
        password    => $opt_pass,
        raw_pty     => 1,
        timeout     => $timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    eval { $ssh->login() };
    if ($@ || !$ssh->is_connected()) {
        output(sprintf("%-20s  [ERROR] Connection/auth failed: %s", $host, $@));
        return { %result, status => 'ERROR' };
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|\#', 5);

    # CPU utilization
    $ssh->send("show processes cpu | include CPU utilization");
    my $cpu_out = $ssh->waitfor('\$|\#', 10) // '';
    my ($cpu5s, $cpu1m, $cpu5m) = ('?', '?', '?');
    if ($cpu_out =~ /CPU utilization.*?:\s*(\d+)%\/\S+;\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%/) {
        ($cpu5s, $cpu1m, $cpu5m) = ($1, $2, $3);
    }

    # Memory utilization
    $ssh->send("show processes memory | include Processor");
    my $mem_out = $ssh->waitfor('\$|\#', 10) // '';
    my ($mem_used, $mem_free, $mem_pct) = (0, 0, 0);
    if ($mem_out =~ /Processor\s+\S+\s+(\d+)\s+(\d+)/) {
        $mem_used = $1; $mem_free = $2;
        my $total = $mem_used + $mem_free;
        $mem_pct  = $total > 0 ? int(($mem_used / $total) * 100) : 0;
    }

    $ssh->close();

    my $warn = ($cpu1m ne '?' && $cpu1m >= $cpu_thresh) ||
               ($mem_pct > 0  && $mem_pct >= $mem_thresh);
    $result{status} = 'WARN' if $warn;

    my $flag = $warn ? '** WARN **' : 'OK';
    output(sprintf("%-20s  %-10s  CPU: %3s%% (1m) %3s%% (5m)  MEM: %3s%% used",
        $host, $flag, $cpu1m, $cpu5m, $mem_pct > 0 ? $mem_pct : '?'));

    return \%result;
}

sub output {
    my ($line) = @_;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}
```