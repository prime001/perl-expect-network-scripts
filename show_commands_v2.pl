#!/usr/bin/perl
#
# cpu_mem_health.pl - Cisco IOS CPU and Memory Health Check
#
# Purpose:
#   Connects to one or more Cisco IOS devices via SSH and collects CPU
#   utilization (5-second, 1-minute, 5-minute averages) and processor memory
#   statistics (used/free). Flags any device exceeding configurable thresholds
#   and exits non-zero if warnings exist, making it suitable for cron/monitoring.
#
# Usage:
#   Single device:  ./cpu_mem_health.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./cpu_mem_health.pl -f devices.txt -u admin -p secret
#   With log:       ./cpu_mem_health.pl -h 192.168.1.1 -u admin -p secret -l health.log
#   Thresholds:     ./cpu_mem_health.pl -h 192.168.1.1 -u admin -p secret --cpu-warn 70 --mem-warn 80
#
# Device file format: one IP or hostname per line; lines starting with # are skipped.
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   Target devices: SSH enabled, user needs at minimum privilege level 1.
#   For enable mode (show processes memory requires priv 15 on some platforms),
#   supply -e with the enable password.

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $enable_pw, $log_file);
my $cpu_warn = 80;
my $mem_warn = 85;
my $timeout  = 30;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$device_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'e|enable=s'  => \$enable_pw,
    'l|log=s'     => \$log_file,
    'cpu-warn=i'  => \$cpu_warn,
    'mem-warn=i'  => \$mem_warn,
    't|timeout=i' => \$timeout,
) or usage();

usage() unless ($host || $device_file) && $username && $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; push @devices, $_ unless /^\s*#/ || /^\s*$/ }
    close $fh;
}
die "No devices to check\n" unless @devices;

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open $log_file: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=" x 70);
out("CPU/Memory Health Check  $ts");
out("Thresholds: CPU >= ${cpu_warn}%   Memory used >= ${mem_warn}%");
out("=" x 70);
out(sprintf("%-22s  %-28s  %s", "Device", "CPU (5s/1m/5m)", "Memory Used%"));
out("-" x 70);

my ($n_ok, $n_warn, $n_err) = (0, 0, 0);

for my $dev (@devices) {
    my $r = poll_device($dev);
    if ($r->{error}) {
        out(sprintf("%-22s  ERROR: %s", $dev, $r->{error}));
        $n_err++;
        next;
    }
    my $cpu_tag = $r->{cpu_5min} >= $cpu_warn ? ' [WARN]' : '';
    my $mem_tag = $r->{mem_pct}  >= $mem_warn ? ' [WARN]' : '';
    out(sprintf("%-22s  %3d%% / %3d%% / %3d%%%-8s  %3d%%%s",
        $dev,
        $r->{cpu_5sec}, $r->{cpu_1min}, $r->{cpu_5min}, $cpu_tag,
        $r->{mem_pct}, $mem_tag,
    ));
    ($cpu_tag || $mem_tag) ? $n_warn++ : $n_ok++;
}

out("=" x 70);
out(sprintf("Summary: %d OK  %d WARNING  %d ERROR  (%d total)",
    $n_ok, $n_warn, $n_err, scalar @devices));
close $log_fh if $log_fh;
exit(($n_warn + $n_err) ? 1 : 0);

# -----------------------------------------------------------------------

sub poll_device {
    my ($dev) = @_;
    my %r = (cpu_5sec => 0, cpu_1min => 0, cpu_5min => 0, mem_pct => 0);

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $dev,
            user     => $username,
            password => $password,
            raw_pty  => 1,
            timeout  => $timeout,
        );
    };
    return { error => "SSH init: $@" } if $@;

    my $banner = eval { $ssh->login() };
    return { error => 'Login failed (bad credentials or unreachable)' }
        unless defined $banner && $banner !~ /[Pp]assword:\s*$/;

    if ($enable_pw) {
        $ssh->send('enable');
        $ssh->waitfor('[Pp]assword', 5);
        $ssh->send($enable_pw);
        $ssh->waitfor('#', 10) or return { error => 'Enable mode failed' };
    }

    $ssh->exec('terminal length 0');

    my $cpu = $ssh->exec('show processes cpu | include CPU utilization');
    # IOS: "CPU utilization for five seconds: 4%/0%; one minute: 6%; five minutes: 5%"
    if ($cpu && $cpu =~ /five seconds:\s*(\d+)%.*?one minute:\s*(\d+)%.*?five minutes:\s*(\d+)%/i) {
        @r{qw(cpu_5sec cpu_1min cpu_5min)} = ($1, $2, $3);
    }

    my $mem = $ssh->exec('show processes memory | include ^Processor');
    # IOS: "Processor  <total>  <used>  <free>  <largest>  <available>"
    if ($mem && $mem =~ /Processor\s+(\d+)\s+(\d+)\s+(\d+)/i) {
        my ($total, $used) = ($1, $2);
        $r{mem_pct} = $total > 0 ? int($used / $total * 100 + 0.5) : 0;
    }

    eval { $ssh->close() };
    return \%r;
}

sub out {
    my ($line) = @_;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}

sub usage {
    die <<'END';
Usage: cpu_mem_health.pl -h <host> | -f <file> -u <user> -p <pass> [options]

  -h, --host       Single device IP or hostname
  -f, --file       File listing devices (one per line, # for comments)
  -u, --user       SSH username
  -p, --pass       SSH password
  -e, --enable     Enable password (required for full memory stats on some IOS)
  -l, --log        Append results to log file
  --cpu-warn <n>   CPU 5-minute % threshold for warning (default: 80)
  --mem-warn <n>   Memory used % threshold for warning (default: 85)
  -t, --timeout    SSH timeout seconds (default: 30)

Exit codes: 0 = all OK,  1 = one or more warnings or errors
END
}