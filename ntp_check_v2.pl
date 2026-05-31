#!/usr/bin/perl
# =============================================================================
# ntp_check_v3.pl - NTP Compliance Auditor for Cisco IOS/IOS-XE
#
# Purpose:
#   Validates NTP configuration against a site compliance policy:
#     - Confirms only approved NTP servers are configured
#     - Verifies sync state and stratum level are within policy limits
#     - Flags clock offset exceeding configurable threshold (default 500ms)
#     - Produces PASS/WARN/FAIL per device suitable for audit reports
#
# Usage:
#   Single device:  ./ntp_check_v3.pl -h 192.168.1.1 -u admin -p secret
#   Device list:    ./ntp_check_v3.pl -f devices.txt -u admin -p secret
#   Full policy:    ./ntp_check_v3.pl -f devices.txt -u admin -p secret \
#                     --approved 10.0.0.10,10.0.0.11 --max-stratum 4 \
#                     --max-offset 200 --log ntp_audit.log
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#
# devices.txt format: one IP or hostname per line; lines starting with # ignored
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file);
my $max_stratum  = 4;
my $max_offset   = 500;
my $approved_str = '';
my $timeout      = 15;

GetOptions(
    'h|host=s'       => \$host,
    'f|file=s'       => \$device_file,
    'u|user=s'       => \$username,
    'p|pass=s'       => \$password,
    'approved=s'     => \$approved_str,
    'max-stratum=i'  => \$max_stratum,
    'max-offset=f'   => \$max_offset,
    'log=s'          => \$log_file,
    't|timeout=i'    => \$timeout,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [--approved IP,IP] [--max-stratum N] [--max-offset MS] [--log FILE]\n";

die "Provide -h HOST or -f FILE\n" unless $host || $device_file;
die "Username required (-u)\n"     unless $username;
die "Password required (-p)\n"     unless $password;

my %approved = map { $_ => 1 } split(/,/, $approved_str) if $approved_str;

my @devices;
if ($host) {
    @devices = ($host);
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } <$fh>;
    chomp @devices;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
    $log_fh->autoflush(1);
}

sub log_out {
    my ($msg) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    print "[$ts] $msg\n";
    print $log_fh "[$ts] $msg\n" if $log_fh;
}

sub check_device {
    my ($dev) = @_;
    $dev =~ s/\s+//g;

    my $ssh = Net::SSH::Expect->new(
        host       => $dev,
        user       => $username,
        password   => $password,
        raw_pty    => 1,
        timeout    => $timeout,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    eval { $ssh->login() };
    if ($@) {
        log_out("FAIL [$dev] Connection/auth error: " . ($@ =~ s/\n/ /gr));
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('(?:>|#)\s*$', 3);

    $ssh->send("show ntp status\n");
    my $ntp_status = $ssh->waitfor('#\s*$', 10) // '';

    $ssh->send("show ntp associations\n");
    my $ntp_assoc = $ssh->waitfor('#\s*$', 10) // '';

    $ssh->send("exit\n");
    $ssh->close();

    my @issues;
    my $result = 'PASS';

    if ($ntp_status =~ /unsynchronized/i || $ntp_status !~ /synchronized/i) {
        push @issues, "NTP unsynchronized";
        $result = 'FAIL';
    }

    if ($ntp_status =~ /stratum\s+(\d+)/i) {
        my $stratum = int($1);
        if ($stratum == 0 || $stratum > $max_stratum) {
            push @issues, "Stratum $stratum exceeds policy max $max_stratum";
            $result = 'FAIL' if $stratum == 0;
            $result = 'WARN' if $result eq 'PASS';
        }
    } else {
        push @issues, "Could not parse stratum";
        $result = 'WARN' if $result eq 'PASS';
    }

    if ($ntp_status =~ /offset\s+(?:of\s+)?([\d.]+)/i) {
        my $offset = $1 + 0;
        if ($offset > $max_offset) {
            push @issues, sprintf("Offset %.1fms > threshold %.0fms", $offset, $max_offset);
            $result = 'WARN' if $result eq 'PASS';
        }
    }

    if (%approved) {
        my %seen;
        while ($ntp_assoc =~ /(\d+\.\d+\.\d+\.\d+)/g) {
            my $peer = $1;
            next if $peer =~ /^127\./ || $seen{$peer}++;
            unless ($approved{$peer}) {
                push @issues, "Unauthorized server $peer";
                $result = 'FAIL';
            }
        }
    }

    my $detail = @issues ? join('; ', @issues) : 'All checks passed';
    log_out("$result [$dev] $detail");
}

log_out("NTP compliance audit started — " . scalar(@devices) . " device(s)");
log_out("Policy: max_stratum=$max_stratum, max_offset=${max_offset}ms" .
        ($approved_str ? ", approved=$approved_str" : ", server_policy=open"));

check_device($_) for @devices;

log_out("Audit complete");
close $log_fh if $log_fh;