```perl
#!/usr/bin/perl
#
# hardware_health.pl - Network Device Hardware Health Monitor
#
# PURPOSE:
#   Collects CPU utilization, memory usage, temperature sensor readings,
#   and power supply status from Cisco IOS/IOS-XE devices. Useful for
#   proactive fault detection and capacity planning before alerts fire.
#
# USAGE:
#   Single device:  ./hardware_health.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./hardware_health.pl -f devices.txt -u admin -p secret
#   With logging:   ./hardware_health.pl -h 192.168.1.1 -u admin -p secret -l health.log
#
# DEVICE FILE FORMAT:
#   One IP or hostname per line; lines beginning with # are ignored.
#
# PREREQUISITES:
#   cpan Net::SSH::Expect Getopt::Long
#   SSH must be enabled on target devices (ip ssh version 2)
#
# THRESHOLDS:
#   CPU 1-min > 80% = WARN, > 95% = CRIT
#   Memory used  > 70% = WARN, > 85% = CRIT
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $pass, $device_file, $log_file);
my $timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'f|file=s'    => \$device_file,
    'l|log=s'     => \$log_file,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h <host> -u <user> -p <pass> [-f <file>] [-l <logfile>] [-t <timeout>]\n";

die "Username required (-u)\n"                          unless $user;
die "Password required (-p)\n"                          unless $pass;
die "Specify a host (-h) or device file (-f)\n"         unless $host || $device_file;

my @devices;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open device file '$device_file': $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*[#;]/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
    die "No valid devices found in $device_file\n" unless @devices;
} else {
    push @devices, $host;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log file '$log_file': $!\n";
}

sub emit {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub check_device {
    my ($device) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);

    emit("\n=== Hardware Health: $device  [$ts] ===\n");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $device,
            user     => $user,
            password => $pass,
            raw_pty  => 1,
            timeout  => $timeout,
        );
        my $banner = $ssh->login();
        if ($banner =~ /[Aa]ccess [Dd]enied|[Bb]ad [Pp]assword|[Aa]uthentication [Ff]ailed/) {
            die "Authentication failed\n";
        }
    };
    if ($@) {
        my $err = $@;
        $err =~ s/\s+$//;
        emit("  [ERROR] $err\n");
        return;
    }

    $ssh->exec("terminal length 0");

    # CPU utilization
    my $cpu = $ssh->exec("show processes cpu | include CPU utilization");
    if ($cpu =~ /five seconds: (\d+)%.*one minute: (\d+)%.*five minutes: (\d+)%/) {
        my ($s5, $m1, $m5) = ($1, $2, $3);
        my $status = ($m1 > 95) ? 'CRIT' : ($m1 > 80) ? 'WARN' : 'OK';
        emit(sprintf("  CPU   : 5sec=%-3d%%  1min=%-3d%%  5min=%-3d%%   [%s]\n",
            $s5, $m1, $m5, $status));
    } else {
        emit("  CPU   : [PARSE ERROR]\n");
    }

    # Memory usage
    my $mem = $ssh->exec("show processes memory | include Processor Pool");
    if ($mem =~ /Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*(\d+)/i) {
        my ($total, $used, $free) = ($1, $2, $3);
        my $pct = $total > 0 ? int($used / $total * 100) : 0;
        my $status = ($pct > 85) ? 'CRIT' : ($pct > 70) ? 'WARN' : 'OK';
        emit(sprintf("  MEMORY: used=%-6d KB  free=%-6d KB  (%d%%)  [%s]\n",
            $used / 1024, $free / 1024, $pct, $status));
    } else {
        emit("  MEMORY: [PARSE ERROR]\n");
    }

    # Temperature
    my $env = $ssh->exec("show environment temperature");
    if ($env =~ /[Cc]ritical|CRITICAL|FAIL/m) {
        emit("  TEMP  : Critical condition detected   [CRIT]\n");
    } elsif ($env =~ /[Nn]ormal|OK|[Gg]reen/mi) {
        emit("  TEMP  : All sensors normal             [OK]\n");
    } else {
        emit("  TEMP  : [NOT AVAILABLE]\n");
    }

    # Power supplies
    my $pwr = $ssh->exec("show environment power");
    if ($pwr =~ /[Ff]ail|FAIL|[Aa]bsent/m) {
        emit("  POWER : Fault or absent supply         [CRIT]\n");
    } elsif ($pwr =~ /[Gg]ood|OK|[Nn]ormal|[Pp]resent/mi) {
        emit("  POWER : All supplies operating OK      [OK]\n");
    } else {
        emit("  POWER : [NOT AVAILABLE]\n");
    }

    # Uptime
    my $ver = $ssh->exec("show version | include uptime");
    if ($ver =~ /uptime is (.+)/) {
        (my $uptime = $1) =~ s/\s+$//;
        emit("  UPTIME: $uptime\n");
    }

    eval { $ssh->close(); };
}

my $total = scalar @devices;
emit("Checking $total device(s)...\n");

check_device($_) for @devices;

emit("\n--- Done: $total device(s) checked ---\n");
close $log_fh if $log_fh;
```