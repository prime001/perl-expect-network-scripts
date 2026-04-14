#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# NTP Compliance Checker for Cisco IOS / IOS-XE Devices
#
# Purpose:
#   Verifies NTP configuration compliance across network devices. Checks that
#   devices are synchronized to approved NTP servers, validates stratum levels,
#   and reports clock offset/drift. Useful for security audits and change
#   management windows where time accuracy is critical.
#
# Usage:
#   ./ntp_compliance_check.pl -h <host>          # single device
#   ./ntp_compliance_check.pl -f <device_list>   # file with one IP per line
#   ./ntp_compliance_check.pl -f hosts.txt -l ntp_audit.log
#   ./ntp_compliance_check.pl -f hosts.txt -s "10.0.1.10,10.0.1.11" -m 3
#
# Options:
#   -h  Single device hostname or IP
#   -f  File containing list of devices (one per line, # for comments)
#   -u  Username (default: netops)
#   -p  Password (prompt if omitted)
#   -l  Log file path (optional)
#   -s  Comma-separated list of approved NTP server IPs
#   -m  Maximum allowed stratum (default: 4)
#   -t  SSH timeout in seconds (default: 15)
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   Devices must have SSH enabled and user must have at least privilege 1.
#
# Author: Network Operations
# =============================================================================

my ($host, $device_file, $log_file);
my $username   = 'netops';
my $password   = '';
my $timeout    = 15;
my $max_stratum = 4;
my $approved_servers_str = '';

GetOptions(
    'h=s' => \$host,
    'f=s' => \$device_file,
    'u=s' => \$username,
    'p=s' => \$password,
    'l=s' => \$log_file,
    's=s' => \$approved_servers_str,
    'm=i' => \$max_stratum,
    't=i' => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile] [-s servers] [-m max_stratum]\n";

die "Specify -h <host> or -f <device_file>\n" unless $host || $device_file;

# Parse approved NTP servers
my %approved_servers;
if ($approved_servers_str) {
    $approved_servers{$_} = 1 for split(/,/, $approved_servers_str);
}

# Prompt for password if not supplied
unless ($password) {
    system('stty', '-echo');
    print "Password for $username: ";
    chomp($password = <STDIN>);
    system('stty', 'echo');
    print "\n";
}

# Build device list
my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close($fh);
}

# Open log file if specified
my $LOG;
if ($log_file) {
    open($LOG, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $separator = '=' x 70;
log_print("$separator");
log_print("NTP Compliance Check  |  $timestamp");
log_print("Max stratum: $max_stratum  |  Approved servers: " .
    ($approved_servers_str || 'any'));
log_print("$separator");

my ($pass_count, $fail_count) = (0, 0);

for my $device (@devices) {
    log_print("\n[+] Connecting to $device ...");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $device,
            user        => $username,
            password    => $password,
            raw_pty     => 1,
            timeout     => $timeout,
            ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
    };
    if ($@ || !$ssh) {
        log_print("    [ERROR] SSH object creation failed: $@");
        $fail_count++;
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !$login) {
        log_print("    [ERROR] Authentication failed or timeout for $device");
        $fail_count++;
        next;
    }

    # Disable paging
    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$', 3);

    # Gather NTP associations
    $ssh->send("show ntp associations\n");
    my $assoc_output = $ssh->waitfor('\$', $timeout) // '';

    # Gather NTP status
    $ssh->send("show ntp status\n");
    my $status_output = $ssh->waitfor('\$', $timeout) // '';

    $ssh->close();

    # Parse sync status
    my $synchronized = ($status_output =~ /Clock is synchronized/i) ? 1 : 0;
    my ($stratum)    = ($status_output =~ /stratum\s+(\d+)/i);
    my ($offset)     = ($status_output =~ /offset\s+([\-\d\.]+)/i);
    my ($ref_server) = ($status_output =~ /reference is\s+([\d\.]+)/i);

    $stratum //= 'unknown';
    $offset  //= 'unknown';
    $ref_server //= 'unknown';

    # Parse peer list from associations output
    my @peers;
    for my $line (split /\n/, $assoc_output) {
        if ($line =~ /[\*\+\-\s~]([\d\.]+)\s/) {
            push @peers, $1;
        }
    }

    # Evaluate compliance
    my @violations;
    push @violations, "NOT synchronized" unless $synchronized;
    push @violations, "Stratum $stratum exceeds max $max_stratum"
        if $stratum ne 'unknown' && $stratum > $max_stratum;

    if (%approved_servers && $ref_server ne 'unknown') {
        unless ($approved_servers{$ref_server}) {
            push @violations, "Reference server $ref_server not in approved list";
        }
    }

    my $status_str  = $synchronized ? 'SYNCED' : 'NOT SYNCED';
    my $comply_str  = @violations   ? 'FAIL'   : 'PASS';
    $comply_str eq 'PASS' ? $pass_count++ : $fail_count++;

    log_print("    Status    : $status_str");
    log_print("    Stratum   : $stratum");
    log_print("    Offset    : ${offset}ms") if $offset ne 'unknown';
    log_print("    Reference : $ref_server");
    log_print("    Peers     : " . (scalar @peers ? join(', ', @peers) : 'none'));
    log_print("    Compliance: $comply_str");
    if (@violations) {
        log_print("    Violations:");
        log_print("      - $_") for @violations;
    }
}

log_print("\n$separator");
log_print(sprintf("Summary: %d device(s) checked | PASS: %d | FAIL: %d",
    scalar @devices, $pass_count, $fail_count));
log_print("$separator\n");

close($LOG) if $LOG;
exit($fail_count > 0 ? 1 : 0);

sub log_print {
    my ($msg) = @_;
    print "$msg\n";
    print $LOG "$msg\n" if $LOG;
}