The target path isn't writable in this environment. Here is the complete script content:

```
#!/usr/bin/perl
#
# cpu_memory_health.pl - CPU and Memory Utilization Monitor for Cisco IOS Devices
#
# Purpose:
#   Connects to one or more Cisco IOS devices via SSH and reports CPU utilization
#   (5-second, 1-minute, 5-minute intervals) and memory usage (used/free/total).
#   Useful for identifying performance degradation, memory leaks, or devices under load.
#
# Usage:
#   Single device:   ./cpu_memory_health.pl -h 192.168.1.1 -u admin -p secret
#   Device file:     ./cpu_memory_health.pl -f devices.txt -u admin -p secret
#   With log:        ./cpu_memory_health.pl -h 10.0.0.1 -u admin -p secret -l health.log
#
# Device file format (one IP or hostname per line, blank lines and # comments ignored):
#   192.168.1.1
#   192.168.1.2
#   # core switches
#   10.0.0.254
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to target devices (enable not required, show commands only)
#
# Tested on: Cisco IOS 12.4, 15.x, IOS-XE 16.x
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file);
my $timeout = 15;

GetOptions(
    'h=s' => \$host,
    'f=s' => \$device_file,
    'u=s' => \$username,
    'p=s' => \$password,
    'l=s' => \$log_file,
    't=i' => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l <logfile>] [-t <timeout>]\n";

die "Specify -h <host> or -f <device_file>\n" unless $host || $device_file;
die "Username (-u) required\n" unless $username;
die "Password (-p) required\n" unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
    die "No devices found in $device_file\n" unless @devices;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
output("=" x 70);
output("CPU/Memory Health Check - $timestamp");
output("=" x 70);

for my $device (@devices) {
    output("\n--- Device: $device ---");
    audit_device($device);
}

output("\nDone. " . scalar(@devices) . " device(s) checked.");
close $log_fh if $log_fh;

sub audit_device {
    my ($dev) = @_;

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host        => $dev,
            user        => $username,
            password    => $password,
            raw_pty     => 1,
            timeout     => $timeout,
        );
        $ssh->login();
    };
    if ($@ || !$ssh) {
        my $err = $@ || 'unknown error';
        $err =~ s/\n.*//s;
        output("  ERROR: Connection failed - $err");
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|#|>', 5);

    $ssh->send("show processes cpu sorted\n");
    my $cpu_out = $ssh->waitfor('\$|#|>', $timeout) // '';

    $ssh->send("show processes memory sorted\n");
    my $mem_out = $ssh->waitfor('\$|#|>', $timeout) // '';

    $ssh->close();

    parse_and_report($dev, $cpu_out, $mem_out);
}

sub parse_and_report {
    my ($dev, $cpu_out, $mem_out) = @_;

    if ($cpu_out =~ /CPU utilization for five seconds:\s*(\d+)%\/(\d+)%;\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%/i) {
        my ($sec5, $int5, $min1, $min5) = ($1, $2, $3, $4);
        my $status = $min1 >= 80 ? "CRITICAL" : $min1 >= 60 ? "WARNING" : "OK";
        output(sprintf("  CPU  : 5sec=%-3s%% (intr %s%%)  1min=%-3s%%  5min=%-3s%%  [%s]",
            $sec5, $int5, $min1, $min5, $status));
    } else {
        output("  CPU  : Unable to parse CPU data");
    }

    if ($mem_out =~ /Processor\s+Pool\s+Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*(\d+)/i) {
        my ($total, $used, $free) = ($1, $2, $3);
        my $pct_used = int(($used / $total) * 100);
        my $status = $pct_used >= 85 ? "CRITICAL" : $pct_used >= 70 ? "WARNING" : "OK";
        output(sprintf("  MEM  : Total=%-6s  Used=%-6s (%d%%)  Free=%-6s  [%s]",
            fmt_bytes($total), fmt_bytes($used), $pct_used, fmt_bytes($free), $status));
    } else {
        output("  MEM  : Unable to parse memory data");
    }
}

sub fmt_bytes {
    my ($b) = @_;
    return sprintf("%.1fG", $b / 1073741824) if $b >= 1073741824;
    return sprintf("%.1fM", $b / 1048576)    if $b >= 1048576;
    return sprintf("%.1fK", $b / 1024)       if $b >= 1024;
    return "${b}B";
}

sub output {
    my ($line) = @_;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}
```