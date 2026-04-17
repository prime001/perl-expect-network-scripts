#!/usr/bin/perl
#
# ntp_compliance_check.pl - NTP Policy Compliance Checker
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices and validates NTP configuration
#   against a defined policy baseline. Checks configured NTP servers against
#   approved server list, verifies synchronization status, reports stratum
#   levels and clock offset, and flags policy violations.
#
# Usage:
#   Single device:   ./ntp_compliance_check.pl -h 192.168.1.1
#   Device list:     ./ntp_compliance_check.pl -f devices.txt
#   With log:        ./ntp_compliance_check.pl -f devices.txt -l ntp_audit.log
#   Custom policy:   ./ntp_compliance_check.pl -f devices.txt -p ntp_policy.txt
#
# Prerequisites:
#   - Net::SSH::Expect (cpan install Net::SSH::Expect)
#   - SSH access to devices with credentials in environment or config
#   - CISCO_USER / CISCO_PASS environment variables (or edit defaults below)
#
# Policy file format (one NTP server IP per line):
#   10.0.0.1
#   10.0.0.2
#
# Author: Network Automation
# Version: 1.0

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# --- Configuration ---
my $SSH_USER  = $ENV{CISCO_USER} // 'admin';
my $SSH_PASS  = $ENV{CISCO_PASS} // 'cisco';
my $TIMEOUT   = 15;
my $MAX_STRATUM = 5;    # Alert if stratum exceeds this
my $MAX_OFFSET  = 1000; # Alert if offset (ms) exceeds this

# Default approved NTP servers (override with -p policy file)
my @DEFAULT_POLICY = qw(10.0.1.100 10.0.1.101);

# --- CLI Options ---
my ($host, $device_file, $log_file, $policy_file);
GetOptions(
    'h|host=s'   => \$host,
    'f|file=s'   => \$device_file,
    'l|log=s'    => \$log_file,
    'p|policy=s' => \$policy_file,
) or die "Usage: $0 [-h host] [-f device_file] [-l log_file] [-p policy_file]\n";

die "Specify -h <host> or -f <file>\n" unless $host || $device_file;

# --- Setup ---
my @devices = $host ? ($host) : load_list($device_file);
my @policy_servers = $policy_file ? load_list($policy_file) : @DEFAULT_POLICY;
my %policy_set = map { $_ => 1 } @policy_servers;

my $timestamp = strftime('%Y%m%d_%H%M%S', localtime);
my $LOG;
if ($log_file) {
    open($LOG, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

log_msg("=== NTP Compliance Check - $timestamp ===");
log_msg("Policy servers: " . join(', ', @policy_servers));
log_msg("");

# --- Main Loop ---
my ($pass_count, $fail_count) = (0, 0);

for my $device (@devices) {
    log_msg("--- $device ---");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $device,
            user        => $SSH_USER,
            password     => $SSH_PASS,
            ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
            timeout     => $TIMEOUT,
            raw_pty     => 1,
        );
    };
    if ($@) {
        log_msg("  ERROR: SSH init failed - $@");
        $fail_count++;
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !$login) {
        log_msg("  ERROR: Login failed - check credentials");
        $fail_count++;
        next;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#', 5);

    # Get NTP status
    $ssh->send("show ntp status");
    my $ntp_status = $ssh->waitfor('\$|#', 10) // '';

    # Get NTP associations
    $ssh->send("show ntp associations");
    my $ntp_assoc = $ssh->waitfor('\$|#', 10) // '';

    $ssh->send("exit");

    # Parse sync status
    my $synced = 0;
    my $stratum = 'unknown';
    my $offset  = 'unknown';
    my $ref_server = 'none';

    if ($ntp_status =~ /Clock is synchronized/i) {
        $synced = 1;
        ($stratum)    = $ntp_status =~ /stratum\s+(\d+)/i;
        ($offset)     = $ntp_status =~ /offset\s+([+-]?\d+\.?\d*)/i;
        ($ref_server) = $ntp_status =~ /reference is\s+(\S+)/i;
    }

    # Parse configured servers from associations
    my @configured;
    for my $line (split /\n/, $ntp_assoc) {
        next unless $line =~ /^\*?~?\+?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
        push @configured, $1;
    }

    # Evaluate compliance
    my @violations;
    push @violations, "NOT SYNCHRONIZED" unless $synced;
    push @violations, "Stratum $stratum exceeds max $MAX_STRATUM"
        if $synced && $stratum =~ /^\d+$/ && $stratum > $MAX_STRATUM;
    push @violations, "Offset ${offset}ms exceeds max ${MAX_OFFSET}ms"
        if $synced && $offset =~ /^[+-]?\d/ && abs($offset) > $MAX_OFFSET;

    for my $srv (@configured) {
        push @violations, "Unauthorized NTP server: $srv"
            unless $policy_set{$srv};
    }

    for my $approved (@policy_servers) {
        push @violations, "Missing approved server: $approved"
            unless grep { $_ eq $approved } @configured;
    }

    # Report
    log_msg(sprintf("  Sync: %-4s  Stratum: %-3s  Offset: %-10s  Ref: %s",
        $synced ? 'YES' : 'NO', $stratum, "${offset}ms", $ref_server));
    log_msg("  Configured: " . (@configured ? join(', ', @configured) : 'none'));

    if (@violations) {
        log_msg("  STATUS: FAIL");
        log_msg("  VIOLATIONS:");
        log_msg("    - $_") for @violations;
        $fail_count++;
    } else {
        log_msg("  STATUS: PASS");
        $pass_count++;
    }
    log_msg("");
}

log_msg("=== Summary: PASS=$pass_count  FAIL=$fail_count  TOTAL=" . scalar(@devices) . " ===");
close($LOG) if $LOG;
exit($fail_count > 0 ? 1 : 0);

# --- Helpers ---

sub load_list {
    my ($file) = @_;
    open(my $fh, '<', $file) or die "Cannot open $file: $!\n";
    my @items = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
    return @items;
}

sub log_msg {
    my ($msg) = @_;
    print "$msg\n";
    print $LOG "$msg\n" if $LOG;
}