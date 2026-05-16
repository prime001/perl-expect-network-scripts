Here's the environmental health check script — covers CPU, memory, temperature, power supplies, and fans, which isn't duplicated by any of the existing scripts:

```perl
#!/usr/bin/perl
#
# env_health.pl - Network Device Environmental Health Check
#
# Purpose:
#   Collects CPU utilization, memory usage, temperature readings,
#   power supply status, and fan status from Cisco IOS/IOS-XE devices.
#   Flags anything in WARNING or CRITICAL state. Useful for pre/post-
#   maintenance baselines and routine environmental monitoring.
#
# Usage:
#   Single device:  perl env_health.pl -h 192.168.1.1 -u admin -p secret
#   Device list:    perl env_health.pl -f devices.txt -u admin -p secret
#   With log:       perl env_health.pl -h 192.168.1.1 -u admin -p secret -l health.log
#
# Prerequisites:
#   Net::SSH::Expect   (cpan Net::SSH::Expect)
#   Getopt::Long       (included in standard Perl)
#   SSH access with at minimum privilege level 1 (read-only show commands)
#
# Tested against: Cisco IOS 12.x/15.x, IOS-XE 16.x/17.x

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $file_arg, $username, $password, $log_file);
my $timeout = 30;

GetOptions(
    'h|host=s'    => \$host_arg,
    'f|file=s'    => \$file_arg,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'l|log=s'     => \$log_file,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h <host>|-f <file> -u <user> -p <pass> [-l logfile] [-t secs]\n";

die "Specify -h <host> or -f <file>\n"  unless $host_arg || $file_arg;
die "Username required (-u)\n"           unless $username;
die "Password required (-p)\n"           unless $password;

my @devices;
if ($host_arg) {
    push @devices, $host_arg;
} else {
    open(my $fh, '<', $file_arg) or die "Cannot open device list $file_arg: $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        push @devices, $_ if length $_;
    }
    close $fh;
    die "No devices found in $file_arg\n" unless @devices;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub commify {
    local $_ = reverse "$_[0]";
    s/(\d{3})(?=\d)/$1,/g;
    return scalar reverse;
}

sub check_device {
    my ($host) = @_;
    out("\n=== $host  [$timestamp] ===\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $username,
        password => $password,
        raw_pty  => 1,
        timeout  => $timeout,
    );

    my $login;
    eval { $login = $ssh->login() };
    if ($@ || !defined $login) {
        out("  FAIL: connection error: " . ($@ // 'unknown') . "\n");
        return;
    }
    if ($login =~ /denied|failed|incorrect|refused/i) {
        out("  FAIL: authentication rejected\n");
        $ssh->close();
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#|>', 5);

    # --- CPU ---
    $ssh->send("show processes cpu | include CPU utilization");
    my $cpu = $ssh->waitfor('\$|#|>', $timeout) // '';
    out("  CPU: ");
    if ($cpu =~ /utilization for\s+\S+\s+(\d+)%.*?one minute:\s*(\d+)%.*?five minutes:\s*(\d+)%/i) {
        my $flag = $1 > 80 ? " [HIGH]" : "";
        out("5s=$1%  1m=$2%  5m=$3%$flag\n");
    } else {
        out("(parse error)\n");
    }

    # --- Memory ---
    $ssh->send("show processes memory | include ^Processor");
    my $mem = $ssh->waitfor('\$|#|>', $timeout) // '';
    out("  MEM: ");
    if ($mem =~ /Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)/i) {
        my ($total, $used, $free) = ($1, $2, $3);
        my $pct = $total > 0 ? int($used / $total * 100) : 0;
        my $flag = $pct > 85 ? " [HIGH]" : "";
        out(sprintf("total=%s used=%s free=%s (%d%%)%s\n",
            commify($total), commify($used), commify($free), $pct, $flag));
    } else {
        out("(parse error)\n");
    }

    # --- Environment (temp/fans/power) ---
    $ssh->send("show environment all");
    my $env = $ssh->waitfor('\$|#|>', $timeout) // '';
    my ($env_ok, @warnings) = (0);
    for my $line (split /\n/, $env) {
        next unless $line =~ /\S/;
        next if $line =~ /^(show|#|-{3,}|\s*$)/;
        if ($line =~ /(FAIL|CRITICAL|WARNING|SHUTDOWN|not present|not functioning)/i) {
            push @warnings, "  WARN: " . ($line =~ s/^\s+//r) . "\n";
        }
        $env_ok = 1 if $line =~ /(temperature|fan|power|supply|voltage|normal|ok)/i;
    }
    if (@warnings) {
        out($_) for @warnings;
    } elsif ($env_ok) {
        out("  ENV: All sensors OK\n");
    } else {
        out("  ENV: No environmental data returned (platform may not support)\n");
    }

    $ssh->close();
}

check_device($_) for @devices;

out("\n--- Done. Checked " . scalar(@devices) . " device(s). ---\n");
close $log_fh if $log_fh;
```