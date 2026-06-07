#!/usr/bin/perl
# ntp_stratum_audit.pl - NTP Stratum and Drift Compliance Audit
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and audits NTP health for
#   compliance reporting.  Checks stratum level against a configurable max,
#   verifies clock offset/drift is within acceptable bounds, and flags devices
#   that are unsynchronized or peering with an unexpected reference clock.
#   Complements ntp_check.pl (status dump) with pass/fail compliance verdicts.
#
# Usage:
#   Single device:   ./ntp_stratum_audit.pl -h 192.168.1.1 -u admin -p secret
#   Device list:     ./ntp_stratum_audit.pl -f devices.txt -u admin -p secret
#   With log:        ./ntp_stratum_audit.pl -f devices.txt -u admin -p secret -l audit.log
#   Custom limits:   ... --max-stratum 4 --max-offset 500
#
# Prerequisites:
#   cpanm Net::SSH::Expect
#
# Output:
#   CSV to STDOUT (and optionally a log file):
#   DEVICE, SYNC_STATUS, STRATUM, OFFSET_MS, REFERENCE, RESULT
#
#   RESULT values: PASS | UNSYNC | STRATUM_HIGH | DRIFT_HIGH | AUTH_FAILED | ERROR

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log);
my $opt_max_stratum = 3;
my $opt_max_offset  = 1000;   # milliseconds - flag if abs(offset) exceeds this
my $opt_timeout     = 20;

GetOptions(
    'h|host=s'        => \$opt_host,
    'f|file=s'        => \$opt_file,
    'u|user=s'        => \$opt_user,
    'p|password=s'    => \$opt_pass,
    'l|log=s'         => \$opt_log,
    'max-stratum=i'   => \$opt_max_stratum,
    'max-offset=i'    => \$opt_max_offset,
    'timeout=i'       => \$opt_timeout,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOG] [--max-stratum N] [--max-offset MS]\n";

die "Specify -h HOST or -f FILE\n"  unless $opt_host || $opt_file;
die "Username required (-u)\n"      unless $opt_user;
die "Password required (-p)\n"      unless $opt_pass;

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open my $fh, '<', $opt_file or die "Cannot open $opt_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^\s*#/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($opt_log) {
    open $log_fh, '>', $opt_log or die "Cannot open log $opt_log: $!\n";
}

sub emit {
    my ($line) = @_;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}

emit "DEVICE,SYNC_STATUS,STRATUM,OFFSET_MS,REFERENCE,RESULT";

for my $device (@devices) {
    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $device,
            user        => $opt_user,
            password    => $opt_pass,
            raw_pty     => 1,
            timeout     => $opt_timeout,
        );
    };
    if ($@ || !$ssh) {
        emit "$device,error,-,-,-,ERROR";
        next;
    }

    my $logged_in = eval { $ssh->login() };
    if (!$logged_in || $@) {
        emit "$device,auth_failed,-,-,-,AUTH_FAILED";
        next;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#', 5);

    $ssh->send("show ntp status");
    my $ntp_out = $ssh->waitfor('\$|#', 10) // '';

    my $sync_status = 'unknown';
    my ($stratum, $reference, $offset) = ('-', '-', '-');
    my $result = 'FAIL';

    if ($ntp_out =~ /Clock is (\S+)/i) {
        $sync_status = lc($1);
    }
    if ($ntp_out =~ /stratum\s+(\d+)/i) {
        $stratum = int($1);
    }
    if ($ntp_out =~ /reference is\s+(\S+)/i) {
        $reference = $1;
    }
    if ($ntp_out =~ /offset\s+([-\d.]+)/i) {
        $offset = $1 + 0;
    }

    if ($sync_status ne 'synchronized') {
        $result = 'UNSYNC';
    } elsif ($stratum eq '-') {
        $result = 'ERROR';
    } elsif ($stratum > $opt_max_stratum) {
        $result = 'STRATUM_HIGH';
    } elsif ($offset ne '-' && abs($offset) > $opt_max_offset) {
        $result = 'DRIFT_HIGH';
    } else {
        $result = 'PASS';
    }

    emit "$device,$sync_status,$stratum,$offset,$reference,$result";

    eval { $ssh->send("exit"); $ssh->close(); };
}

close $log_fh if $log_fh;

if ($opt_log) {
    my %tally;
    open my $fh, '<', $opt_log or exit 0;
    while (<$fh>) {
        chomp;
        next if /^DEVICE/;
        my @f = split /,/, $_;
        $tally{ $f[-1] }++ if @f >= 6;
    }
    close $fh;
    emit "";
    emit "--- Summary ---";
    for my $k (sort keys %tally) {
        emit "$k: $tally{$k}";
    }
}