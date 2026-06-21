#!/usr/bin/perl
#
# hardware_health.pl - Network Device Hardware Health Check
#
# PURPOSE:
#   Polls Cisco IOS/IOS-XE devices for hardware environmental status:
#   CPU utilization, memory usage, power supply and fan status, and
#   temperature sensor readings. Flags any readings outside acceptable
#   thresholds with a WARN or CRIT label.
#
# USAGE:
#   Single device:   ./hardware_health.pl -h 192.168.1.1 -u admin -p secret
#   Device file:     ./hardware_health.pl -f devices.txt -u admin -p secret
#   With log:        ./hardware_health.pl -h 10.0.0.1 -u admin -p secret -l /var/log/hw_health.log
#
# PREREQUISITES:
#   cpan Expect Getopt::Long
#
# DEVICE FILE FORMAT (devices.txt):
#   One IP or hostname per line; lines starting with # are ignored.
#
# EXIT CODES:
#   0 = all devices OK
#   1 = one or more warnings or criticals detected
#   2 = one or more connection failures
#

use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $logfile, $timeout);
$timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$file,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'l|log=s'      => \$logfile,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOGFILE] [-t TIMEOUT]\n";

die "Provide -h HOST or -f FILE\n"      unless $host || $file;
die "Username (-u) required\n"          unless $user;
die "Password (-p) required\n"          unless $pass;

my @devices;
if ($file) {
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    while (<$fh>) { chomp; next if /^\s*#/ || /^\s*$/; push @devices, $_; }
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!\n";
}

my $ts        = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $exit_code = 0;

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub check_device {
    my ($device) = @_;

    out("\n=== $device  [$ts] ===\n");

    my $exp = Expect->new;
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=$timeout $user\@$device")) {
        out("  [ERROR] Failed to spawn SSH for $device\n");
        return 2;
    }

    my $result = $exp->expect($timeout,
        [ qr/[Pp]assword:/         => sub { $exp->send("$pass\n"); exp_continue; } ],
        [ qr/yes\/no/              => sub { $exp->send("yes\n");   exp_continue; } ],
        [ qr/[>#]\s*$/             => sub { } ],
        [ timeout                  => sub { out("  [ERROR] Timeout connecting to $device\n"); return 2; } ],
        [ qr/[Pp]ermission denied/ => sub { out("  [ERROR] Auth failed for $device\n");      return 2; } ],
    );

    unless (defined $result) {
        out("  [ERROR] Connection failed: $device\n");
        return 2;
    }

    $exp->send("terminal length 0\n");
    $exp->expect($timeout, qr/[>#]\s*$/);

    my $device_exit = 0;

    my %commands = (
        cpu    => 'show processes cpu | include CPU utilization',
        mem    => 'show processes memory | include Processor',
        env    => 'show environment all',
    );

    for my $key (qw(cpu mem env)) {
        $exp->send("$commands{$key}\n");
        $exp->expect($timeout, qr/[>#]\s*$/);
        my $out = $exp->before();

        if ($key eq 'cpu') {
            if ($out =~ /CPU utilization for five seconds:\s*(\d+)%.*one minute:\s*(\d+)%.*five minutes:\s*(\d+)%/) {
                my ($s5, $m1, $m5) = ($1, $2, $3);
                my $status = ($m5 >= 80) ? 'CRIT' : ($m5 >= 60) ? 'WARN' : 'OK';
                $device_exit = 1 if $status ne 'OK';
                out(sprintf("  CPU  [%s] 5s:%d%% 1m:%d%% 5m:%d%%\n", $status, $s5, $m1, $m5));
            } else {
                out("  CPU  [UNKNOWN] Could not parse CPU output\n");
            }
        }

        if ($key eq 'mem') {
            if ($out =~ /Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)/) {
                my ($total, $used, $free) = ($1, $2, $3);
                my $pct = ($total > 0) ? int($used / $total * 100) : 0;
                my $status = ($pct >= 85) ? 'CRIT' : ($pct >= 70) ? 'WARN' : 'OK';
                $device_exit = 1 if $status ne 'OK';
                out(sprintf("  MEM  [%s] Used:%dKB Free:%dKB (%d%%)\n",
                    $status, $used/1024, $free/1024, $pct));
            } else {
                out("  MEM  [UNKNOWN] Could not parse memory output\n");
            }
        }

        if ($key eq 'env') {
            my @lines = split /\n/, $out;
            for my $line (@lines) {
                if ($line =~ /FAIL|Critical|Absent|Shutdown/i && $line !~ /^\s*$/) {
                    (my $clean = $line) =~ s/^\s+|\s+$//g;
                    out("  ENV  [CRIT] $clean\n");
                    $device_exit = 1;
                } elsif ($line =~ /Warning/i) {
                    (my $clean = $line) =~ s/^\s+|\s+$//g;
                    out("  ENV  [WARN] $clean\n");
                    $device_exit = 1 if $device_exit == 0;
                } elsif ($line =~ /Temperature|Fan|Power/i && $line =~ /OK|Normal|Present/i) {
                    (my $clean = $line) =~ s/^\s+|\s+$//g;
                    out("  ENV  [OK]   $clean\n");
                }
            }
        }
    }

    $exp->send("exit\n");
    $exp->soft_close();

    out("  --- " . ($device_exit == 0 ? "ALL OK" : "ISSUES DETECTED") . " ---\n");
    return $device_exit;
}

for my $dev (@devices) {
    my $rc = check_device($dev);
    $exit_code = $rc if $rc > $exit_code;
}

out("\n[Done] Checked " . scalar(@devices) . " device(s) at $ts\n");
close $log_fh if $log_fh;
exit $exit_code;