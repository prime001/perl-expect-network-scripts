#!/usr/bin/perl
#
# ntp_check_v2.pl - Advanced NTP Compliance and Drift Analyzer
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and performs a comprehensive
#   NTP health check: verifies clock synchronization, evaluates stratum level,
#   measures offset/drift against configurable thresholds, and checks peer count.
#   Outputs a pass/warn/fail compliance summary per device.
#
# Usage:
#   Single device:  perl ntp_check_v2.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    perl ntp_check_v2.pl -f devices.txt -u admin -p secret
#   With log file:  perl ntp_check_v2.pl -f devices.txt -u admin -p secret -l ntp_report.log
#
# Device file format (one IP/hostname per line, # for comments):
#   192.168.1.1
#   192.168.1.2  # core-sw-01
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH key-based auth or password auth must be available
#   User account needs privilege level 1 (show commands only)
#
# Thresholds (adjust to match your NTP policy):
#   MAX_STRATUM   - highest acceptable stratum (default: 4)
#   MAX_OFFSET_MS - max clock offset in milliseconds (default: 500)
#   MIN_PEERS     - minimum synced peer count (default: 1)
#
# Author: Erik Anderson
# Version: 2.0
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# --- Thresholds ---
use constant MAX_STRATUM   => 4;
use constant MAX_OFFSET_MS => 500;
use constant MIN_PEERS     => 1;

# --- Argument Parsing ---
my ($host, $device_file, $username, $password, $log_file);
GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$log_file,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l <logfile>]\n";

die "Provide -h or -f\n"  unless $host || $device_file;
die "Username required\n" unless $username;
die "Password required\n" unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        s/#.*//;   # strip comments
        s/\s+.*//; # strip inline notes
        push @devices, $_ if /\S/;
    }
    close $fh;
}

# --- Logging Setup ---
my $log_fh;
if ($log_file) {
    open($log_fh, '>', $log_file) or die "Cannot open log $log_file: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("NTP Compliance Report - $timestamp");
output("=" x 60);

# --- Process Each Device ---
my ($pass_count, $warn_count, $fail_count) = (0, 0, 0);

for my $device (@devices) {
    output("\nDevice: $device");
    output("-" x 40);

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $username,
        password => $password,
        raw_pty  => 1,
        timeout  => 15,
    );

    eval {
        my $login = $ssh->login();
        if ($login !~ /[>#]/) {
            die "Authentication failed or unexpected prompt\n";
        }

        # Disable paging
        $ssh->exec("terminal length 0");

        # Gather NTP status
        my $ntp_status = $ssh->exec("show ntp status");
        my $ntp_assoc  = $ssh->exec("show ntp associations");

        # Parse synchronization state
        my $synced  = ($ntp_status =~ /Clock is synchronized/i)  ? 1 : 0;
        my $stratum = ($ntp_status =~ /stratum\s+(\d+)/i)        ? $1 : 99;
        my $offset  = ($ntp_status =~ /offset\s+([-\d.]+)/i)     ? $1 : 9999;
        $offset = abs($offset);

        # Count synced peers (lines starting with '*' or '+' in associations)
        my $peer_count = () = ($ntp_assoc =~ /^[*+]/mg);

        # Evaluate compliance
        my @issues;
        push @issues, "NOT SYNCHRONIZED"           unless $synced;
        push @issues, "Stratum $stratum > " . MAX_STRATUM  if $stratum > MAX_STRATUM;
        push @issues, "Offset ${offset}ms > " . MAX_OFFSET_MS . "ms" if $offset > MAX_OFFSET_MS;
        push @issues, "Only $peer_count synced peer(s), min " . MIN_PEERS if $peer_count < MIN_PEERS;

        my $status;
        if (!$synced || @issues >= 2) {
            $status = "FAIL";
            $fail_count++;
        } elsif (@issues) {
            $status = "WARN";
            $warn_count++;
        } else {
            $status = "PASS";
            $pass_count++;
        }

        output(sprintf("  Status   : %s", $status));
        output(sprintf("  Synced   : %s", $synced ? "Yes" : "No"));
        output(sprintf("  Stratum  : %s", $stratum == 99 ? "unknown" : $stratum));
        output(sprintf("  Offset   : %.2f ms", $offset));
        output(sprintf("  Peers    : %d synced", $peer_count));
        output("  Issues   : " . join(", ", @issues)) if @issues;

        $ssh->close();
    };

    if ($@) {
        my $err = $@;
        $err =~ s/\n/ /g;
        output("  ERROR: $err");
        $fail_count++;
    }
}

# --- Summary ---
output("\n" . "=" x 60);
output(sprintf("Summary: %d PASS  %d WARN  %d FAIL  (of %d devices)",
    $pass_count, $warn_count, $fail_count, scalar @devices));
output("Report generated: $timestamp");

close $log_fh if $log_fh;
exit($fail_count > 0 ? 2 : $warn_count > 0 ? 1 : 0);

sub output {
    my ($line) = @_;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}