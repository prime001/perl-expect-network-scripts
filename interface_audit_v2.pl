```perl
#!/usr/bin/perl
#
# health_check.pl - Network Device Hardware Health Monitor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and collects hardware health
#   metrics: CPU utilization (5-min avg), memory usage percentage, temperature
#   sensor readings, and power supply status. Flags values exceeding thresholds
#   with a leading '!' in output.
#
# Usage:
#   Single device:  ./health_check.pl -h 192.168.1.1 -u admin [-p password] [-l logfile]
#   Device list:    ./health_check.pl -f devices.txt -u admin [-p password] [-l logfile]
#
# Device file format: one IP or hostname per line; blank lines and # comments ignored
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH key auth recommended (omit -p); password auth supported via -p
#
# Thresholds (edit below): CPU 80%, Memory 85%, Temperature 55C

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);

my %opts;
getopts('h:f:u:p:l:t:', \%opts);

my $user    = $opts{u} or die "Usage: $0 -h <host>|-f <file> -u <user> [-p pass] [-l log] [-t timeout]\n";
my $pass    = $opts{p} // '';
my $logfile = $opts{l} // '';
my $timeout = $opts{t} // 30;

my @devices;
if ($opts{h}) {
    push @devices, $opts{h};
} elsif ($opts{f}) {
    open my $fh, '<', $opts{f} or die "Cannot open $opts{f}: $!\n";
    while (<$fh>) { chomp; next if /^\s*$/ || /^#/; push @devices, $_; }
    close $fh;
} else {
    die "Specify -h <host> or -f <device_file>\n";
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open logfile $logfile: $!\n";
}

my $CPU_WARN  = 80;
my $MEM_WARN  = 85;
my $TEMP_WARN = 55;

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
out("=" x 68);
out("Health Check: $ts");
out("=" x 68);
printf "%-22s %-12s %-12s %-10s %-8s\n", "Device", "CPU5min%", "MemUsed%", "TempC", "PSU";
printf "%s\n", "-" x 68;

for my $host (@devices) {
    my ($cpu, $mem, $temp, $psu) = check_device($host);
    my $cs = defined $cpu  ? ($cpu  >= $CPU_WARN  ? "!$cpu"  : $cpu)  : 'ERR';
    my $ms = defined $mem  ? ($mem  >= $MEM_WARN  ? "!$mem"  : $mem)  : 'ERR';
    my $ts2 = defined $temp ? ($temp >= $TEMP_WARN ? "!$temp" : $temp) : 'N/A';
    my $ps = $psu // 'ERR';
    printf "%-22s %-12s %-12s %-10s %-8s\n", $host, $cs, $ms, $ts2, $ps;
    out(sprintf "%-22s cpu=%-5s mem=%-5s temp=%-6s psu=%s", $host, $cs, $ms, $ts2, $ps);
}
out("=" x 68 . "\n");
close $log_fh if $log_fh;

sub check_device {
    my ($host) = @_;
    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        user       => $user,
        password   => $pass,
        raw_pty    => 1,
        timeout    => $timeout,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );
    eval { $pass ? $ssh->login() : $ssh->login_no_password() };
    if ($@) {
        warn "[$host] SSH failed: $@\n";
        return (undef, undef, undef, 'NOCONN');
    }
    $ssh->exec("terminal length 0");
    my ($cpu, $mem, $temp, $psu) = (get_cpu($ssh), get_mem($ssh), get_temp($ssh), get_psu($ssh));
    eval { $ssh->close() };
    return ($cpu, $mem, $temp, $psu);
}

sub get_cpu {
    my ($ssh) = @_;
    my $out = $ssh->exec("show processes cpu | include CPU utilization") // return undef;
    return $1 if $out =~ /five minutes:\s*(\d+)%/;
    return undef;
}

sub get_mem {
    my ($ssh) = @_;
    my $out = $ssh->exec("show processes memory | include Processor") // return undef;
    if ($out =~ /\d+\s+(\d+)\s+(\d+)/) {
        my ($used, $free) = ($1, $2);
        return int($used / ($used + $free) * 100) if ($used + $free) > 0;
    }
    return undef;
}

sub get_temp {
    my ($ssh) = @_;
    my $out = $ssh->exec("show environment temperature") // return undef;
    my $max;
    while ($out =~ /(\d{2,3})\s*(?:Celsius|C\b)/gi) {
        $max = $1 if !defined $max || $1 > $max;
    }
    return $max;
}

sub get_psu {
    my ($ssh) = @_;
    my $out = $ssh->exec("show environment power") // return 'N/A';
    return 'FAIL' if $out =~ /fail|absent|critical/i;
    return 'OK'   if $out =~ /normal|good|present|ok/i;
    return 'N/A';
}

sub out {
    my ($msg) = @_;
    print $log_fh "$msg\n" if $log_fh;
}
```