#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# ntp_drift_audit.pl - NTP Offset and Stratum Compliance Auditor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices and audits NTP health against
#   configurable thresholds. Flags devices with excessive clock drift,
#   high stratum values, or unsynchronized state. Useful for pre-change
#   validation and compliance sweeps.
#
# Usage:
#   ./ntp_drift_audit.pl -h 192.168.1.1 -u admin -p secret
#   ./ntp_drift_audit.pl -f devices.txt -u admin -p secret -l audit.log
#   ./ntp_drift_audit.pl -h 10.0.0.1 -u admin -p secret --warn-ms 50 --crit-ms 200
#
# Prerequisites:
#   cpan Net::SSH::Expect
#
# Thresholds (defaults):
#   WARNING  : offset > 100ms or stratum > 4
#   CRITICAL : offset > 500ms or stratum > 8 or not synchronized

my ($host, $user, $pass, $device_file, $log_file);
my $warn_ms   = 100;
my $crit_ms   = 500;
my $warn_strat = 4;
my $crit_strat = 8;
my $timeout   = 20;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'l|log=s'      => \$log_file,
    'warn-ms=i'    => \$warn_ms,
    'crit-ms=i'    => \$crit_ms,
    't|timeout=i'  => \$timeout,
) or die "Invalid options. Use -h host or -f file, -u user, -p pass\n";

die "Provide -h host or -f file\n" unless $host || $device_file;
die "Provide -u user and -p pass\n" unless $user && $pass;

my @devices = $host ? ($host) : do {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
};

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=" x 60);
output("NTP Drift Audit  |  $timestamp");
output("Thresholds: WARN offset>${warn_ms}ms strat>$warn_strat  CRIT offset>${crit_ms}ms strat>$crit_strat");
output("=" x 60);

my ($ok, $warn, $crit) = (0, 0, 0);

for my $dev (@devices) {
    my $ssh = Net::SSH::Expect->new(
        host        => $dev,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_ok = eval { $ssh->run_ssh() };
    if ($@ || !$login_ok) {
        output(sprintf("%-20s  CRITICAL  connection failed: %s", $dev, $@ // 'unknown'));
        $crit++;
        next;
    }

    $ssh->waitfor('>\s*$|#\s*$', 5) or do {
        output(sprintf("%-20s  CRITICAL  prompt not found", $dev));
        $crit++;
        next;
    };
    $ssh->send("terminal length 0\n");
    $ssh->waitfor('#\s*$', 5);

    $ssh->send("show ntp status\n");
    my $status_out = $ssh->waitfor('#\s*$', 15) // '';

    $ssh->send("show ntp associations\n");
    my $assoc_out  = $ssh->waitfor('#\s*$', 15) // '';

    $ssh->send("exit\n");
    $ssh->close();

    my $synced   = ($status_out =~ /Clock is synchronized/i) ? 1 : 0;
    my ($offset) = ($status_out =~ /offset of ([\d.]+) msec/i);
    my ($strat)  = ($status_out =~ /stratum (\d+)/i);
    my ($refclock)= ($status_out =~ /reference is ([\d.]+)/i);

    $offset  //= 0;
    $strat   //= 16;
    $refclock //= 'unknown';

    my $level;
    my @flags;

    push @flags, "NOT-SYNCED"             unless $synced;
    push @flags, "offset=${offset}ms"     if $offset > $warn_ms;
    push @flags, "stratum=$strat"         if $strat  > $warn_strat;

    if (!$synced || $offset > $crit_ms || $strat > $crit_strat) {
        $level = 'CRITICAL';
        $crit++;
    } elsif (@flags) {
        $level = 'WARNING';
        $warn++;
    } else {
        $level = 'OK';
        $ok++;
    }

    my $detail = $level eq 'OK'
        ? "synced refclock=$refclock stratum=$strat offset=${offset}ms"
        : join(' ', @flags) . " refclock=$refclock";

    output(sprintf("%-20s  %-8s  %s", $dev, $level, $detail));
}

output("-" x 60);
output(sprintf("Summary: %d OK  %d WARNING  %d CRITICAL  (%d total)",
    $ok, $warn, $crit, scalar @devices));

close $log_fh if $log_fh;
exit($crit ? 2 : $warn ? 1 : 0);

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}