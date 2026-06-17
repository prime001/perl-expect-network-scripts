#!/usr/bin/perl
# ==============================================================================
# cpu_memory_health.pl - Network Device CPU/Memory Health Monitor
# ==============================================================================
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and collects CPU utilization
#   and memory usage statistics. Flags devices exceeding configurable thresholds.
#   Exit code: 0=all OK, 1=warnings present, 2=critical conditions found.
#
# Usage:
#   Single device:  ./cpu_memory_health.pl -h 192.168.1.1
#   Device list:    ./cpu_memory_health.pl -f devices.txt -u netops -l health.log
#   Custom limits:  ./cpu_memory_health.pl -f devices.txt --cpu-crit 85 --mem-warn 80
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH key auth recommended; use -p to supply password interactively.
#
# Options:
#   -h <host>       Single target device IP or hostname
#   -f <file>       File with device IPs, one per line (# for comments)
#   -u <user>       SSH username (default: admin)
#   -p <pass>       SSH password (prompted securely if omitted)
#   -l <logfile>    Append results to this file in addition to STDOUT
#   -t <secs>       SSH timeout in seconds (default: 30)
#   --cpu-warn <N>  CPU 1-min avg warning threshold % (default: 70)
#   --cpu-crit <N>  CPU 1-min avg critical threshold % (default: 90)
#   --mem-warn <N>  Memory used warning threshold % (default: 75)
#   --mem-crit <N>  Memory used critical threshold % (default: 90)
# ==============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case bundling);
use POSIX        qw(strftime);

my ($opt_host, $opt_file, $opt_log, $opt_user, $opt_pass);
my $opt_timeout = 30;
my ($cpu_warn, $cpu_crit, $mem_warn, $mem_crit) = (70, 90, 75, 90);
$opt_user = 'admin';

GetOptions(
    'h=s'        => \$opt_host,
    'f=s'        => \$opt_file,
    'u=s'        => \$opt_user,
    'p=s'        => \$opt_pass,
    'l=s'        => \$opt_log,
    't=i'        => \$opt_timeout,
    'cpu-warn=i' => \$cpu_warn,
    'cpu-crit=i' => \$cpu_crit,
    'mem-warn=i' => \$mem_warn,
    'mem-crit=i' => \$mem_crit,
) or die "Usage error — see script header for options.\n";

die "Specify -h <host> or -f <file>\n" unless $opt_host || $opt_file;

unless ($opt_pass) {
    local $| = 1;
    print "SSH password for $opt_user: ";
    system('stty -echo');
    chomp($opt_pass = <STDIN>);
    system('stty echo');
    print "\n";
}

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open my $fh, '<', $opt_file or die "Cannot open $opt_file: $!\n";
    while (<$fh>) { chomp; s/^\s+|\s+$//g; push @devices, $_ if $_ && !/^#/; }
    close $fh;
}

my $log_fh;
if ($opt_log) {
    open $log_fh, '>>', $opt_log or die "Cannot open log $opt_log: $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
out("=" x 62 . "\n");
out("CPU/Memory Health Check  $ts\n");
out("Thresholds — CPU: warn=${cpu_warn}% crit=${cpu_crit}%  Mem: warn=${mem_warn}% crit=${mem_crit}%\n");
out("=" x 62 . "\n\n");

my ($n_ok, $n_warn, $n_crit, $n_err) = (0, 0, 0, 0);

for my $device (@devices) {
    out("[$device]\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host       => $device,
            user       => $opt_user,
            password   => $opt_pass,
            raw_pty    => 1,
            timeout    => $opt_timeout,
            ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
    };
    unless ($ssh && eval { $ssh->login() }) {
        out("  ERROR: Connection/auth failed — ${\($@ // 'unknown')}\n\n");
        $n_err++;
        next;
    }

    $ssh->exec("terminal length 0");

    # Hostname from 'show version'
    my $hostname = $device;
    my $ver = $ssh->exec("show version | include uptime");
    $hostname = $1 if $ver && $ver =~ /^(\S+)\s+uptime/m;

    # CPU — IOS: "CPU utilization for five seconds: 12%/4%; one minute: 8%; five minutes: 6%"
    my $cpu_out = $ssh->exec("show processes cpu | include CPU utilization");
    my ($cpu_5s, $cpu_1m, $cpu_5m) = (0, 0, 0);
    if ($cpu_out && $cpu_out =~ /five seconds:\s*(\d+)%.*?one minute:\s*(\d+)%.*?five minutes:\s*(\d+)%/s) {
        ($cpu_5s, $cpu_1m, $cpu_5m) = ($1, $2, $3);
    }

    # Memory — IOS: "Processor Pool Total: NNN Used: NNN Free: NNN"
    my $mem_out = $ssh->exec("show processes memory | include Processor Pool");
    my ($mem_total, $mem_used, $mem_pct) = (0, 0, 0);
    if ($mem_out && $mem_out =~ /Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*\d+/m) {
        ($mem_total, $mem_used) = ($1, $2);
        $mem_pct = int($mem_used / $mem_total * 100) if $mem_total;
    }

    $ssh->close();

    my $cpu_st  = $cpu_1m >= $cpu_crit ? 'CRIT' : $cpu_1m >= $cpu_warn ? 'WARN' : 'OK';
    my $mem_st  = $mem_pct >= $mem_crit ? 'CRIT' : $mem_pct >= $mem_warn ? 'WARN' : 'OK';
    my $overall = ($cpu_st eq 'CRIT' || $mem_st eq 'CRIT') ? 'CRIT'
                : ($cpu_st eq 'WARN' || $mem_st eq 'WARN') ? 'WARN' : 'OK';

    out(sprintf("  Hostname : %s\n", $hostname));
    out(sprintf("  CPU      : [%-4s] 5s=%d%%  1m=%d%%  5m=%d%%\n", $cpu_st, $cpu_5s, $cpu_1m, $cpu_5m));
    out(sprintf("  Memory   : [%-4s] %dMB used / %dMB total (%d%%)\n",
        $mem_st, int($mem_used / 1_048_576), int($mem_total / 1_048_576), $mem_pct));
    out(sprintf("  Overall  : %s\n\n", $overall));

    $overall eq 'CRIT' ? $n_crit++ : $overall eq 'WARN' ? $n_warn++ : $n_ok++;
}

out("-" x 62 . "\n");
out(sprintf("Summary: %d OK  |  %d WARN  |  %d CRIT  |  %d ERROR  (%d devices)\n",
    $n_ok, $n_warn, $n_crit, $n_err, scalar @devices));
out("-" x 62 . "\n");

close $log_fh if $log_fh;
exit($n_crit ? 2 : $n_warn ? 1 : 0);