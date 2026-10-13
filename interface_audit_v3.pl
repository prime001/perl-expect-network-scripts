#!/usr/bin/perl
#
# interface_errors.pl - Interface Error Counter Auditor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices and audits interface error counters.
#   Flags interfaces exceeding configurable thresholds for CRC errors, input
#   errors, output drops, runts, and giants. Identifies duplex mismatches,
#   faulty cables, and oversubscribed uplinks before they cause outages.
#
# Usage:
#   ./interface_errors.pl <device_ip>
#   ./interface_errors.pl --file devices.txt [--user netops] [--log errors.log]
#   ./interface_errors.pl 10.0.1.1 --threshold 50 --log /tmp/audit.log
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   Set NETOPS_USER and NETOPS_PASS env vars to avoid interactive prompts.
#
# Exit codes: 0=all clear, 1=errors found above threshold, 2=connection failure

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my %THRESHOLD = (
    crc         => 10,
    input_err   => 50,
    output_drop => 25,
    runts       => 5,
    giants      => 5,
);

my ($file, $user, $log_file, $threshold_override);
GetOptions(
    'file=s'      => \$file,
    'user=s'      => \$user,
    'log=s'       => \$log_file,
    'threshold=i' => \$threshold_override,
) or die "Usage: $0 <device_ip> [--file FILE] [--user USER] [--log FILE] [--threshold N]\n";

$user //= $ENV{NETOPS_USER} // 'admin';
my $password = $ENV{NETOPS_PASS};

my @devices;
if ($file) {
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } <$fh>;
    chomp @devices;
    close $fh;
} elsif (@ARGV) {
    push @devices, $ARGV[0];
} else {
    die "Usage: $0 <device_ip> [--file devices.txt] [--user USER] [--log FILE]\n";
}

unless ($password) {
    system "stty -echo 2>/dev/null";
    print "SSH password for $user: ";
    chomp($password = <STDIN>);
    print "\n";
    system "stty echo 2>/dev/null";
}

if ($threshold_override) {
    $THRESHOLD{$_} = $threshold_override for keys %THRESHOLD;
}

my $LOG;
if ($log_file) {
    open $LOG, '>>', $log_file or die "Cannot open log '$log_file': $!\n";
}

sub emit {
    my ($msg) = @_;
    print $msg;
    print $LOG $msg if $LOG;
}

my $timestamp     = strftime("%Y-%m-%d %H:%M:%S", localtime);
my $total_flagged = 0;
my $exit_code     = 0;

for my $host (@devices) {
    $host =~ s/^\s+|\s+$//g;
    next unless length $host;

    emit("\n[$timestamp] $host\n" . "-" x 50 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        user       => $user,
        password   => $password,
        raw_pty    => 1,
        timeout    => 20,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    unless (eval { $ssh->login() }) {
        emit("  FAILED: Cannot connect to $host ($@)\n");
        $exit_code = 2 unless $exit_code == 1;
        next;
    }

    $ssh->exec("terminal length 0");
    my $output = $ssh->exec("show interfaces") // '';
    $ssh->close();

    if (!$output || $output !~ /\S/) {
        emit("  ERROR: Empty response from $host\n");
        next;
    }

    my (%counters, $iface);
    for my $line (split /\n/, $output) {
        if ($line =~ /^(\S+(?:\/\S+)*)\s+is\s+(?:up|down|admin)/) {
            $iface = $1;
        }
        next unless $iface;
        if ($line =~ /(\d+) input errors.*?(\d+) CRC/i) {
            $counters{$iface}{input_err} = $1;
            $counters{$iface}{crc}       = $2;
        }
        if ($line =~ /(\d+) output drops/i) {
            $counters{$iface}{output_drop} = $1;
        }
        if ($line =~ /(\d+) runts.*?(\d+) giants/i) {
            $counters{$iface}{runts}  = $1;
            $counters{$iface}{giants} = $2;
        }
    }

    my $flagged = 0;
    for my $intf (sort keys %counters) {
        my @alerts;
        for my $counter (sort keys %THRESHOLD) {
            my $val = $counters{$intf}{$counter} // 0;
            push @alerts, sprintf("%s=%d(>%d)", $counter, $val, $THRESHOLD{$counter})
                if $val > $THRESHOLD{$counter};
        }
        if (@alerts) {
            emit(sprintf("  ALERT  %-28s %s\n", $intf, join("  ", @alerts)));
            $flagged++;
            $total_flagged++;
            $exit_code = 1;
        }
    }

    my $iface_count = scalar keys %counters;
    emit("  OK     No interfaces exceeded error thresholds\n") unless $flagged;
    emit(sprintf("  Checked %d interfaces, %d flagged\n", $iface_count, $flagged));
}

emit("\n[$timestamp] Done — $total_flagged total interface(s) flagged across " . scalar(@devices) . " device(s)\n");
close $LOG if $LOG;
exit $exit_code;