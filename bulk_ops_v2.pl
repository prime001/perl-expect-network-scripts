#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# cpu_memory_health.pl - Bulk CPU & Memory Health Checker for Cisco IOS/IOS-XE
#
# PURPOSE:
#   Connects to one or more Cisco routers/switches via SSH and collects CPU
#   utilization (5-second, 1-minute, 5-minute intervals) and memory usage
#   (processor pool free/total). Flags devices exceeding configurable thresholds.
#   Useful for capacity planning, incident triage, and scheduled health checks.
#
# USAGE:
#   Single device:   ./cpu_memory_health.pl -h 192.168.1.1 -u admin -p secret
#   Device file:     ./cpu_memory_health.pl -f devices.txt -u admin -p secret
#   With logging:    ./cpu_memory_health.pl -f devices.txt -u admin -p secret -l health.log
#   Custom thresholds: ./cpu_memory_health.pl -f devices.txt -u admin -p secret \
#                        --cpu-warn 70 --mem-warn 80
#
# PREREQUISITES:
#   - Perl modules: Net::SSH::Expect, Getopt::Long (cpan install Net::SSH::Expect)
#   - SSH access to devices with 'show processes cpu' and 'show processes memory' privilege
#   - Devices file format: one IP or hostname per line, lines starting with # are ignored
#
# OUTPUT:
#   Tab-separated results to STDOUT and optional log file.
#   WARNING prefix on lines exceeding thresholds.
# =============================================================================

my ($host, $device_file, $username, $password, $logfile);
my $cpu_warn  = 75;
my $mem_warn  = 85;
my $timeout   = 20;

GetOptions(
    'h|host=s'      => \$host,
    'f|file=s'      => \$device_file,
    'u|user=s'      => \$username,
    'p|pass=s'      => \$password,
    'l|log=s'       => \$logfile,
    'cpu-warn=i'    => \$cpu_warn,
    'mem-warn=i'    => \$mem_warn,
    't|timeout=i'   => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l logfile]\n";

die "ERROR: Specify -h <host> or -f <file>\n"      unless $host || $device_file;
die "ERROR: Username (-u) required\n"               unless $username;
die "ERROR: Password (-p) required\n"               unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "ERROR: Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

my $LOG;
if ($logfile) {
    open($LOG, '>>', $logfile) or die "ERROR: Cannot open log $logfile: $!\n";
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
my $header = sprintf("%-20s %-12s %-10s %-10s %-10s %-12s %-12s %s",
    "HOST", "CPU_5SEC%", "CPU_1MIN%", "CPU_5MIN%", "MEM_TOTAL", "MEM_FREE", "MEM_USED%", "STATUS");

output("=" x 95);
output("CPU & MEMORY HEALTH CHECK  --  $ts");
output("Thresholds: CPU warn >=${cpu_warn}%  |  Memory used warn >=${mem_warn}%");
output("=" x 95);
output($header);
output("-" x 95);

for my $device (@devices) {
    check_device($device);
}

output("=" x 95);
close $LOG if $LOG;

sub check_device {
    my ($dev) = @_;
    my $ssh = Net::SSH::Expect->new(
        host        => $dev,
        user        => $username,
        password    => $password,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    eval {
        my $login = $ssh->login();
        unless ($login =~ /[>#]/) {
            die "Auth failed or unexpected prompt\n";
        }
        $ssh->send("terminal length 0");
        $ssh->waitfor('[>#]', 5);

        $ssh->send("show processes cpu | include CPU utilization");
        my $cpu_out = $ssh->waitfor('[>#]', $timeout) // '';

        $ssh->send("show processes memory | include Processor");
        my $mem_out = $ssh->waitfor('[>#]', $timeout) // '';

        $ssh->send("exit");

        my ($cpu5s, $cpu1m, $cpu5m) = ('N/A', 'N/A', 'N/A');
        if ($cpu_out =~ /(\d+)%\/(\d+)%;\s+one minute:\s+(\d+)%;\s+five minutes:\s+(\d+)%/) {
            ($cpu5s, $cpu1m, $cpu5m) = ($1, $3, $4);
        } elsif ($cpu_out =~ /five seconds:\s+(\d+)%.*?one minute:\s+(\d+)%.*?five minutes:\s+(\d+)%/s) {
            ($cpu5s, $cpu1m, $cpu5m) = ($1, $2, $3);
        }

        my ($mem_total, $mem_free, $mem_pct) = ('N/A', 'N/A', 'N/A');
        if ($mem_out =~ /Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)/) {
            $mem_total = $1;
            $mem_free  = $3;
            $mem_pct   = int(($mem_total - $mem_free) / $mem_total * 100) if $mem_total > 0;
        }

        my $status = 'OK';
        if ($cpu5m ne 'N/A' && $cpu5m >= $cpu_warn) { $status = "WARN:CPU_HIGH(${cpu5m}%)"; }
        if ($mem_pct ne 'N/A' && $mem_pct >= $mem_warn) {
            $status = ($status eq 'OK') ? "WARN:MEM_HIGH(${mem_pct}%)" : "$status,MEM_HIGH(${mem_pct}%)";
        }

        my $line = sprintf("%-20s %-12s %-10s %-10s %-12s %-12s %-12s %s",
            $dev, $cpu5s, $cpu1m, $cpu5m,
            format_bytes($mem_total), format_bytes($mem_free), "${mem_pct}%", $status);
        output($line);
    };
    if ($@) {
        my $err = $@; $err =~ s/\n/ /g;
        output(sprintf("%-20s %-76s %s", $dev, "CONNECT_ERROR", $err));
    }
}

sub format_bytes {
    my ($b) = @_;
    return $b if $b eq 'N/A';
    return sprintf("%.1fM", $b / 1048576) if $b >= 1048576;
    return sprintf("%.1fK", $b / 1024)    if $b >= 1024;
    return "${b}B";
}

sub output {
    my ($line) = @_;
    print "$line\n";
    print $LOG "$line\n" if $LOG;
}