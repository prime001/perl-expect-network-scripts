#!/usr/bin/perl
# =============================================================================
# cpu_mem_health.pl - Cisco IOS/IOS-XE CPU and Memory Health Monitor
# =============================================================================
# Purpose:
#   SSH to one or more Cisco devices, collect CPU utilization (5s/1m/5m
#   intervals) and processor memory statistics, and flag any device exceeding
#   configurable thresholds. Suitable for NOC dashboards or cron alerting.
#
# Usage:
#   Single device:  ./cpu_mem_health.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./cpu_mem_health.pl -f devices.txt -u admin -p secret
#   With log:       ./cpu_mem_health.pl -f devices.txt -u admin -p secret -l health.log
#   Custom thresh:  ./cpu_mem_health.pl -h 10.0.0.1 -u admin -p secret -c 70 -m 80
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#   SSH access to target devices; Cisco IOS 12.4+ / IOS-XE 3.x+ / IOS-XR
#
# Device file format: one IP or hostname per line; lines starting with # ignored
#
# Exit codes: 0 = all OK, 1 = threshold exceeded, 2 = connection/auth error
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file);
my $cpu_warn    = 80;
my $mem_warn    = 85;
my $ssh_timeout = 15;
my $cmd_timeout = 10;

GetOptions(
    'h|host=s' => \$host,
    'f|file=s' => \$device_file,
    'u|user=s' => \$username,
    'p|pass=s' => \$password,
    'l|log=s'  => \$log_file,
    'c|cpu=i'  => \$cpu_warn,
    'm|mem=i'  => \$mem_warn,
) or die usage();

die usage() unless ($host || $device_file) && $username && $password;

my @devices;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if $_ }
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

my $ts        = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $exit_code = 0;

out("=" x 70);
out("CPU/Memory Health Check  --  $ts");
out("Thresholds: CPU(5m) >= ${cpu_warn}%   Memory >= ${mem_warn}%");
out("=" x 70);

for my $dev (@devices) {
    out("\n[ $dev ]");
    my $r = poll_device($dev);

    if ($r->{error}) {
        out("  ERROR: $r->{error}");
        $exit_code = 2 unless $exit_code == 2;
        next;
    }

    out(sprintf "  Hostname     : %s",               $r->{hostname} || 'unknown');
    out(sprintf "  CPU  5s/1m/5m: %s%% / %s%% / %s%%", $r->{cpu_5s}, $r->{cpu_1m}, $r->{cpu_5m});
    out(sprintf "  Memory       : %s KB used / %s KB free / %s KB total (%s%% used)",
        $r->{mem_used}, $r->{mem_free}, $r->{mem_total}, $r->{mem_pct});

    my @alerts;
    push @alerts, "CPU 5m=$r->{cpu_5m}% >= ${cpu_warn}% threshold" if $r->{cpu_5m} >= $cpu_warn;
    push @alerts, "Memory $r->{mem_pct}% used >= ${mem_warn}% threshold" if $r->{mem_pct} >= $mem_warn;

    if (@alerts) {
        out("  *** ALERT: " . join('; ', @alerts) . " ***");
        $exit_code = 1 unless $exit_code == 2;
    } else {
        out("  Status       : OK");
    }
}

out("\n" . "=" x 70);
out(sprintf "Scan complete. Checked: %d device(s)", scalar @devices);
out("=" x 70);
close $log_fh if $log_fh;
exit $exit_code;

# ---------------------------------------------------------------------------

sub poll_device {
    my ($dev) = @_;
    my %r;

    my $ssh = Net::SSH::Expect->new(
        host       => $dev,
        user       => $username,
        password   => $password,
        raw_pty    => 1,
        timeout    => $ssh_timeout,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    eval {
        my $out = $ssh->login();
        die "Authentication failed\n" if $out =~ /Permission denied|Authentication failed/i;
    };
    if ($@) {
        (my $msg = $@) =~ s/\n.*//s;
        $r{error} = "SSH login failed: $msg";
        return \%r;
    }

    send_cmd($ssh, 'terminal length 0');

    # Grab hostname from prompt
    $ssh->send('');
    my $prompt = $ssh->waitfor('\S+[#>]', 3) // '';
    $r{hostname} = ($prompt =~ /(\S+)[#>]\s*$/) ? $1 : 'unknown';

    # CPU
    my $cpu = send_cmd($ssh, 'show processes cpu | include CPU utilization');
    if ($cpu =~ /five seconds:\s*(\d+)%.*one minute:\s*(\d+)%.*five minutes:\s*(\d+)%/s) {
        @r{qw(cpu_5s cpu_1m cpu_5m)} = ($1, $2, $3);
    } else {
        @r{qw(cpu_5s cpu_1m cpu_5m)} = (0, 0, 0);
    }

    # Memory — IOS: 'show processes memory | include Processor'
    my $mem = send_cmd($ssh, 'show processes memory | include Processor');
    if ($mem =~ /Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)/s) {
        my ($total_b, $used_b, $free_b) = ($1, $2, $3);
        @r{qw(mem_total mem_used mem_free)} = map { int($_ / 1024) } ($total_b, $used_b, $free_b);
        $r{mem_pct} = $r{mem_total} > 0 ? int($r{mem_used} / $r{mem_total} * 100) : 0;
    } else {
        # IOS-XE fallback: parse 'show platform resources'
        my $plat = send_cmd($ssh, 'show platform resources | include DRAM');
        if ($plat =~ /DRAM\s+(\d+)\s+MB.*?(\d+)%/s) {
            $r{mem_total} = $1 * 1024;
            $r{mem_pct}   = $2;
            $r{mem_used}  = int($r{mem_total} * $2 / 100);
            $r{mem_free}  = $r{mem_total} - $r{mem_used};
        } else {
            @r{qw(mem_total mem_used mem_free mem_pct)} = (0, 0, 0, 0);
        }
    }

    eval { $ssh->close() };
    return \%r;
}

sub send_cmd {
    my ($ssh, $cmd) = @_;
    $ssh->send($cmd);
    return $ssh->waitfor('\S+[#>]', $cmd_timeout) // '';
}

sub out {
    print "$_[0]\n";
    print $log_fh "$_[0]\n" if $log_fh;
}

sub usage {
    return <<'END';
Usage: cpu_mem_health.pl -h <host> -u <user> -p <pass> [options]
       cpu_mem_health.pl -f <device_file> -u <user> -p <pass> [options]
Options:
  -h, --host    Device IP or hostname
  -f, --file    File with one device per line
  -u, --user    SSH username
  -p, --pass    SSH password
  -l, --log     Append output to log file
  -c, --cpu     CPU 5-min alert threshold % (default 80)
  -m, --mem     Memory used alert threshold % (default 85)
END
}