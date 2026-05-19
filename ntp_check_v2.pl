#!/usr/bin/perl
# =============================================================================
# ntp_policy_audit.pl - NTP Policy Compliance Auditor
#
# Purpose:
#   Audits Cisco IOS/IOS-XE devices for NTP policy compliance. Verifies that
#   configured NTP servers match an approved list, stratum levels are within
#   acceptable bounds, and NTP authentication is enabled. Designed for
#   environments where NTP accuracy and security are compliance requirements.
#
# Usage:
#   Single device:   ./ntp_policy_audit.pl -h 192.168.1.1
#   Device list:     ./ntp_policy_audit.pl -f devices.txt
#   With logging:    ./ntp_policy_audit.pl -f devices.txt -l audit.log
#   Custom policy:   ./ntp_policy_audit.pl -f devices.txt -s 10.0.0.1,10.0.0.2 -m 3
#
# Options:
#   -h <host>      Single device IP or hostname
#   -f <file>      File containing device IPs, one per line (# for comments)
#   -l <logfile>   Output log file path (optional)
#   -u <user>      SSH username (default: admin)
#   -p <pass>      SSH password (will prompt if omitted)
#   -s <servers>   Comma-separated approved NTP server IPs to enforce
#   -m <stratum>   Maximum acceptable stratum level (default: 4)
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   cpan Getopt::Long
#
# Output:
#   PASS/FAIL per device with specific policy violations listed.
#   Exit code 0 = all pass, 1 = one or more failures.
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_log, $opt_user, $opt_pass, $opt_servers, $opt_maxstratum);
$opt_user       = 'admin';
$opt_maxstratum = 4;

GetOptions(
    'h=s' => \$opt_host,
    'f=s' => \$opt_file,
    'l=s' => \$opt_log,
    'u=s' => \$opt_user,
    'p=s' => \$opt_pass,
    's=s' => \$opt_servers,
    'm=i' => \$opt_maxstratum,
) or die "Usage: $0 -h <host> | -f <file> [-l log] [-u user] [-p pass] [-s servers] [-m stratum]\n";

die "Specify -h <host> or -f <file>\n" unless $opt_host || $opt_file;

unless ($opt_pass) {
    print "SSH password: ";
    system('stty', '-echo');
    chomp($opt_pass = <STDIN>);
    system('stty', 'echo');
    print "\n";
}

my @approved = $opt_servers ? split(/,\s*/, $opt_servers) : ();

my @devices;
if ($opt_file) {
    open my $fh, '<', $opt_file or die "Cannot open '$opt_file': $!\n";
    while (<$fh>) {
        chomp; s/\s*#.*//;
        push @devices, $_ if /\S/;
    }
    close $fh;
} else {
    @devices = ($opt_host);
}

my $log_fh;
if ($opt_log) {
    open $log_fh, '>', $opt_log or die "Cannot open log '$opt_log': $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
log_out("=" x 68);
log_out("NTP Policy Compliance Audit  --  $ts");
log_out("Max stratum: $opt_maxstratum  |  Approved servers: " .
    (@approved ? join(', ', @approved) : '(any)'));
log_out("=" x 68);

my ($total_pass, $total_fail) = (0, 0);

for my $dev (@devices) {
    log_out("\n[$dev]");
    my @issues = audit_device($dev);
    if (@issues) {
        log_out("  STATUS: FAIL");
        log_out("  - $_") for @issues;
        $total_fail++;
    } else {
        log_out("  STATUS: PASS");
        $total_pass++;
    }
}

my $total = $total_pass + $total_fail;
log_out("\n" . "=" x 68);
log_out(sprintf("Result: %d/%d compliant (%.0f%%)",
    $total_pass, $total, $total ? $total_pass / $total * 100 : 0));
log_out("=" x 68);

close $log_fh if $log_fh;
exit($total_fail ? 1 : 0);

sub audit_device {
    my ($dev) = @_;
    my @issues;

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $dev,
            user     => $opt_user,
            password => $opt_pass,
            raw_pty  => 1,
            timeout  => 20,
        );
    };
    return ("Connection object creation failed: $@") if $@;

    eval { $ssh->login() };
    return ("Authentication failed: $@") if $@;

    $ssh->exec('terminal length 0');

    my $status = $ssh->exec('show ntp status')                        // '';
    my $cfg    = $ssh->exec('show running-config | include ntp')      // '';
    $ssh->close();

    # Sync state
    if ($status =~ /unsynchronized|not synchronized/i || $status !~ /synchronized/i) {
        push @issues, "NTP clock is not synchronized";
    }

    # Stratum level
    if ($status =~ /stratum\s+(\d+)/i) {
        push @issues, "Stratum $1 exceeds policy maximum of $opt_maxstratum"
            if $1 > $opt_maxstratum;
    }

    # Approved server enforcement
    if (@approved) {
        my %approved_map = map { $_ => 1 } @approved;
        my @configured;
        push @configured, $1 while $cfg =~ /ntp\s+server\s+([\d\.]+)/gi;

        for my $s (@configured) {
            push @issues, "Unauthorized NTP server configured: $s"
                unless $approved_map{$s};
        }
        my %configured_map = map { $_ => 1 } @configured;
        for my $s (@approved) {
            push @issues, "Required NTP server missing: $s"
                unless $configured_map{$s};
        }
    }

    # Authentication
    push @issues, "NTP authentication not configured"
        unless $cfg =~ /ntp\s+authenticate\b/i;

    push @issues, "NTP authentication key not defined"
        unless $cfg =~ /ntp\s+authentication-key\s+\d+/i;

    return @issues;
}

sub log_out {
    my ($line) = @_;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}