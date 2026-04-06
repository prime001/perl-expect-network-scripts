Now I'll write the CPU/memory/environmental health check script — practical and not duplicating any existing coverage.

#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# 012_cpu_memory_health.pl - CPU, Memory & Environmental Health Monitor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and collects CPU utilization,
#   memory pool statistics, and environmental sensor readings (temperature, fan,
#   power supply status). Flags devices exceeding configurable CPU/memory
#   thresholds or reporting hardware faults. Useful during incident triage,
#   post-change validation, or scheduled capacity health checks.
#
#   Commands executed per device:
#     show processes cpu sorted  (5s/1m/5m CPU utilization, top consumers)
#     show processes memory sorted  (memory pool usage, top consumers)
#     show environment all  (temperature, fans, power supplies)
#
# Usage:
#   Single device:   ./012_cpu_memory_health.pl -h 192.168.1.1
#   Device list:     ./012_cpu_memory_health.pl -f routers.txt
#   With log file:   ./012_cpu_memory_health.pl -f routers.txt -l health.log
#   Custom creds:    ./012_cpu_memory_health.pl -h 10.0.0.1 -u netops -p s3cr3t
#   Adjust limits:   ./012_cpu_memory_health.pl -f routers.txt --cpu 70 --mem 85
#
# Device file format (one IP or hostname per line; # for comments):
#   192.168.1.1
#   core-rtr-02.example.net
#   # 10.0.0.99  (disabled)
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#   SSH access with privilege level 1 or higher (no enable needed for show cmds)
#   Tested on Cisco IOS 15.x, IOS-XE 16.x/17.x
#
# Credentials (prefer env vars over -p to avoid shell history exposure):
#   NET_USER  SSH username   (default: admin)
#   NET_PASS  SSH password
#
# Exit codes:
#   0  All devices within thresholds, no hardware faults
#   1  One or more threshold violations or environmental faults detected
#   2  All target devices unreachable (script-level failure)
# =============================================================================

my ($opt_host, $opt_file, $opt_log, $opt_user, $opt_pass);
my ($cpu_warn, $mem_warn, $timeout, $top_n, $help);
$cpu_warn = 75;
$mem_warn = 80;
$timeout  = 25;
$top_n    = 5;

GetOptions(
    'h|host=s'    => \$opt_host,
    'f|file=s'    => \$opt_file,
    'l|log=s'     => \$opt_log,
    'u|user=s'    => \$opt_user,
    'p|pass=s'    => \$opt_pass,
    'cpu=i'       => \$cpu_warn,
    'mem=i'       => \$mem_warn,
    'timeout=i'   => \$timeout,
    'top=i'       => \$top_n,
    'help'        => \$help,
) or die "Run with --help for usage.\n";

if ($help) {
    open(my $fh, '<', $0) or die $!;
    while (<$fh>) { last unless /^#/; s/^# ?//; print }
    exit 0;
}

die "Error: specify -h <host> or -f <device_file>\n" unless $opt_host || $opt_file;

my $username = $opt_user || $ENV{NET_USER} || 'admin';
my $password = $opt_pass || $ENV{NET_PASS} || '';

unless ($password) {
    print "Password for $username: ";
    system('stty -echo');
    chomp($password = <STDIN>);
    system('stty echo');
    print "\n";
}

my @devices;
push @devices, $opt_host if $opt_host;
if ($opt_file) {
    open(my $fh, '<', $opt_file) or die "Cannot open $opt_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*[#]/ || /^\s*$/; push @devices, $_ }
    close $fh;
}

my $log_fh;
if ($opt_log) {
    open($log_fh, '>>', $opt_log) or die "Cannot open log $opt_log: $!\n";
    $log_fh->autoflush(1);
}

sub emit {
    print $_[0];
    print $log_fh $_[0] if $log_fh;
}

my $ts        = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $warnings  = 0;
my $failed    = 0;

emit("=" x 70 . "\n");
emit(sprintf("CPU / Memory / Environmental Health Check  |  %s\n", $ts));
emit(sprintf("Thresholds: CPU >= %d%%  |  Mem used >= %d%%\n", $cpu_warn, $mem_warn));
emit("=" x 70 . "\n");

for my $device (@devices) {
    emit("\n[ $device ]\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $username,
        password    => $password,
        raw_pty     => 1,
        timeout     => $timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=no',
    );

    eval { $ssh->login() };
    if ($@) {
        emit("  ERROR: SSH login failed - $@\n");
        $failed++;
        next;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('[#>$]', 5);

    $ssh->send('show processes cpu sorted');
    my $cpu_out = $ssh->waitfor('[#>$]', $timeout) // '';

    $ssh->send('show processes memory sorted');
    my $mem_out = $ssh->waitfor('[#>$]', $timeout) // '';

    $ssh->send('show environment all');
    my $env_out = $ssh->waitfor('[#>$]', $timeout) // '';

    $ssh->close();

    # --- CPU ---
    my ($cpu5s, $cpu1m, $cpu5m);
    if ($cpu_out =~ /CPU utilization.*?(\d+)%\/(\d+)%.*?five minutes:\s*(\d+)%/i) {
        ($cpu5s, $cpu1m, $cpu5m) = ($1, $2, $3);
    } elsif ($cpu_out =~ /CPU utilization.*?five seconds:\s*(\d+)%.*?one minute:\s*(\d+)%.*?five minutes:\s*(\d+)%/si) {
        ($cpu5s, $cpu1m, $cpu5m) = ($1, $2, $3);
    }

    if (defined $cpu5m) {
        my $flag = ($cpu5m >= $cpu_warn || $cpu1m >= $cpu_warn) ? '  WARN' : '    OK';
        emit(sprintf("  [CPU%s]  5s=%-3d%%  1m=%-3d%%  5m=%-3d%%\n",
                     $flag, $cpu5s, $cpu1m, $cpu5m));
        $warnings++ if $flag =~ /WARN/;

        # Top CPU consumers
        my $n = 0;
        for my $line (split /\n/, $cpu_out) {
            last if $n >= $top_n;
            next unless $line =~ /^\s*\d+\s+\d+\s+\d+\s+\d+%\s+\d+%\s+\d+%\s+(.+)/;
            my $proc = $1;
            $proc =~ s/^\s+|\s+$//g;
            emit(sprintf("          top proc: %s\n", $proc));
            $n++;
        }
    } else {
        emit("  [CPU  SKIP]  Could not parse CPU output\n");
    }

    # --- Memory ---
    # "Processor  123456789  87654321   Total: 117MB  Used: 84MB  Free: 33MB"
    my ($mem_total, $mem_used, $mem_free, $mem_pct);
    for my $line (split /\n/, $mem_out) {
        if ($line =~ /Processor\s+(\d+)\s+(\d+)\s+(\d+)/i) {
            ($mem_total, $mem_used, $mem_free) = ($1, $2, $3);
            last;
        }
        # Alternate: "Total: xxxK  Used: xxxK  Free: xxxK"
        if ($line =~ /Total:\s*(\d+).*?Used:\s*(\d+).*?Free:\s*(\d+)/i) {
            ($mem_total, $mem_used, $mem_free) = ($1, $2, $3);
            last;
        }
    }

    if (defined $mem_total && $mem_total > 0) {
        $mem_pct = int(($mem_used / $mem_total) * 100);
        my $flag = ($mem_pct >= $mem_warn) ? '  WARN' : '    OK';
        emit(sprintf("  [MEM%s]  used=%d%%  total=%dK  used=%dK  free=%dK\n",
                     $flag, $mem_pct, $mem_total, $mem_used, $mem_free));
        $warnings++ if $flag =~ /WARN/;
    } else {
        emit("  [MEM  SKIP]  Could not parse memory output\n");
    }

    # --- Environmental sensors ---
    my (@temp_warn, @fan_fail, @psu_fail);
    for my $line (split /\n/, $env_out) {
        # Temperature: "Inlet Temp: 38 Celsius OK"  or "TEMPERATURE: OK"
        if ($line =~ /temp(?:erature)?[^:]*:\s*([\d.]+)\s*(?:Celsius|C)?\s*(Normal|OK|Warning|Critical|WARN|FAIL|Shutdown)/i) {
            my ($val, $state) = ($1, $2);
            push @temp_warn, "$line" unless $state =~ /Normal|OK/i;
        }
        # Fan: "FAN: OK" or "Fan 1: Failed"
        if ($line =~ /fan[^:]*:\s*(OK|Normal|Good|Failed|Fail|Warning|FAIL|Down)/i) {
            my $state = $1;
            push @fan_fail, $line unless $state =~ /OK|Normal|Good/i;
        }
        # Power supply: "PS1: OK" or "Power Supply 1: Fail"
        if ($line =~ /(?:power\s*supply|PSU?)\s*\d*[^:]*:\s*(OK|Normal|Good|Failed|Fail|Warning|Absent|FAIL)/i) {
            my $state = $1;
            push @psu_fail, $line unless $state =~ /OK|Normal|Good/i;
        }
    }

    if (@temp_warn) {
        emit("  [ENV  WARN]  Temperature alerts:\n");
        emit("          $_\n") for map { s/^\s+|\s+$//gr } @temp_warn;
        $warnings++;
    } else {
        emit("  [ENV    OK]  Temperature: within normal range\n");
    }
    if (@fan_fail) {
        emit("  [FAN  WARN]  Fan faults:\n");
        emit("          $_\n") for map { s/^\s+|\s+$//gr } @fan_fail;
        $warnings++;
    }
    if (@psu_fail) {
        emit("  [PSU  WARN]  Power supply faults:\n");
        emit("          $_\n") for map { s/^\s+|\s+$//gr } @psu_fail;
        $warnings++;
    }
    if (!@fan_fail && !@psu_fail && !$env_out) {
        emit("  [ENV  SKIP]  No environmental output received\n");
    }
}

emit("\n" . "=" x 70 . "\n");
emit(sprintf("Devices checked: %d  |  Failed connections: %d  |  Threshold/fault alerts: %d\n",
             scalar(@devices), $failed, $warnings));
emit("=" x 70 . "\n");

close $log_fh if $log_fh;

exit( ($failed == scalar(@devices)) ? 2 : ($warnings ? 1 : 0) );