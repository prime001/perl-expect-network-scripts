#!/usr/bin/perl
# =============================================================================
# stp_check.pl -- Spanning Tree Protocol Topology Verification
# =============================================================================
# Purpose:
#   SSH into Cisco IOS/IOS-XE switches and audit STP state across all active
#   VLANs. Reports root bridge ownership, non-forwarding port counts, and
#   topology change activity that may indicate network instability.
#
#   Useful for: change-window validation, loop troubleshooting, pre/post
#   maintenance checks, and STP health auditing across the access layer.
#
# Usage:
#   ./stp_check.pl <device_ip_or_hostname>
#   ./stp_check.pl --file switches.txt
#   ./stp_check.pl --file switches.txt --user admin --log stp_audit.log
#
# Device list format: one IP/hostname per line; blank lines and # comments ok
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access with privilege-15 (or enable password configured on device)
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my $username = $ENV{LOGNAME} || $ENV{USER} || 'admin';
my ($password, $logfile, $devfile, $timeout) = ('', '', '', 30);

GetOptions(
    'user|u=s'     => \$username,
    'password|p=s' => \$password,
    'log|l=s'      => \$logfile,
    'file|f=s'     => \$devfile,
    'timeout|t=i'  => \$timeout,
) or die "Usage: $0 [--user U] [--file DEVLIST | <host>] [--log FILE]\n";

my @devices;
if ($devfile) {
    open(my $fh, '<', $devfile) or die "Cannot open device list '$devfile': $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if length $_ }
    close $fh;
} elsif (@ARGV) {
    @devices = @ARGV;
} else {
    die "Provide a device hostname/IP or --file <device_list>\n";
}

die "No devices to check.\n" unless @devices;

unless ($password) {
    print "SSH password for $username: ";
    system('stty', '-echo');
    chomp($password = <STDIN>);
    system('stty', 'echo');
    print "\n";
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log '$logfile': $!\n";
}

sub out {
    print @_;
    print $log_fh @_ if $log_fh;
}

sub check_stp {
    my ($host) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);

    out("\n", "=" x 64, "\n");
    out("Device: $host    Checked: $ts\n");
    out("=" x 64, "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $host,
            user     => $username,
            password => $password,
            raw_pty  => 1,
            timeout  => $timeout,
        );
    };
    unless ($ssh) {
        out("ERROR: Failed to create SSH session for $host: $@\n");
        return;
    }

    eval { $ssh->login() };
    if ($@) {
        out("ERROR: Login failed for $host - check credentials or SSH access\n");
        return;
    }

    $ssh->exec("terminal length 0");

    my $summary = $ssh->exec("show spanning-tree summary")           // '';
    my $detail  = $ssh->exec("show spanning-tree")                   // '';
    my $changes = $ssh->exec(
        "show spanning-tree detail | include topology change|number of"
    ) // '';

    $ssh->close();

    # STP operating mode and root bridge ownership
    my $mode    = $summary =~ /Switch is in (\S+) mode/i ? $1 : 'unknown';
    my $is_root = $summary =~ /(\d+)\s+VLANs.*?Root/i    ? $1 : 0;
    my $total   = $summary =~ /of\s+(\d+)\s+VLANs/i      ? $1 : '?';

    out(sprintf("Mode       : %s\n",           $mode));
    out(sprintf("Root bridge: %s of %s active VLANs\n", $is_root, $total));

    # Non-forwarding ports (blocking, listening, learning)
    my @blocking;
    while ($detail =~ /^\s+(\S+)\s+(?:Desg|Root|Altn|Back)\s+(BLK|LIS|LRN)\b/mg) {
        push @blocking, [$1, $2];
    }

    if (@blocking) {
        out(sprintf("Non-fwd ports: %d\n", scalar @blocking));
        out(sprintf("  %-26s %s\n", $_->[0], $_->[1])) for @blocking;
    } else {
        out("Non-fwd ports: none -- all ports forwarding\n");
    }

    # Topology change events (non-zero counters indicate instability)
    my @tc;
    for my $line (split /\n/, $changes) {
        next unless $line =~ /topology change/i && $line =~ /\d+/;
        $line =~ s/^\s+//;
        push @tc, $line;
    }
    if (@tc) {
        out("!! Topology changes detected (possible instability):\n");
        out("   $_\n") for @tc;
    }
}

check_stp($_) for @devices;

close $log_fh if $log_fh;

my $done = strftime('%Y-%m-%d %H:%M:%S', localtime);
out(sprintf("\nDone: %d device(s) checked at %s\n", scalar @devices, $done));