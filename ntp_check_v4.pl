#!/usr/bin/perl
#
# ntp_stratum_audit.pl - NTP Stratum and Offset Compliance Auditor
#
# PURPOSE:
#   Audits NTP health beyond simple sync status — validates stratum level,
#   offset threshold, reference clock, and authentication config across
#   one or more Cisco IOS/IOS-XE devices. Flags devices out of compliance.
#
# USAGE:
#   Single device:  ./ntp_stratum_audit.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./ntp_stratum_audit.pl -f devices.txt -u admin -p secret
#   With log:       ./ntp_stratum_audit.pl -f devices.txt -u admin -p secret -l audit.log
#   Custom limits:  ./ntp_stratum_audit.pl -h 10.0.0.1 -u admin -p secret -s 3 -o 100
#
# OPTIONS:
#   -h HOST     Single device IP or hostname
#   -f FILE     File with one device per line (comments with # supported)
#   -u USER     SSH username
#   -p PASS     SSH password
#   -e PASS     Enable password (optional, defaults to login password)
#   -l FILE     Log file path (optional)
#   -s NUM      Max acceptable stratum (default: 4)
#   -o NUM      Max acceptable offset in ms (default: 200)
#   -t NUM      SSH timeout in seconds (default: 15)
#
# PREREQUISITES:
#   cpan Expect
#   SSH access to devices with 'show ntp status' and 'show ntp associations' rights
#
# EXIT CODES:
#   0 = all devices compliant
#   1 = one or more devices non-compliant or unreachable

use strict;
use warnings;
use Expect;
use Getopt::Std;

my %opts;
getopts('h:f:u:p:e:l:s:o:t:', \%opts);

my $username     = $opts{u} or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS\n";
my $password     = $opts{p} or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS\n";
my $enable_pass  = $opts{e} || $password;
my $logfile      = $opts{l};
my $max_stratum  = $opts{s} || 4;
my $max_offset   = $opts{o} || 200;
my $timeout      = $opts{t} || 15;

my @devices;
if ($opts{h}) {
    push @devices, $opts{h};
} elsif ($opts{f}) {
    open(my $fh, '<', $opts{f}) or die "Cannot open device file '$opts{f}': $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
} else {
    die "Specify -h HOST or -f FILE\n";
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log '$logfile': $!\n";
}

sub log_print {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $overall_status = 0;
my $ts = scalar localtime;
log_print("=" x 70 . "\n");
log_print("NTP Stratum/Offset Compliance Audit  $ts\n");
log_print("Thresholds: stratum<=$max_stratum  offset<=${max_offset}ms\n");
log_print("=" x 70 . "\n\n");

for my $host (@devices) {
    log_print("Device: $host\n");
    log_print("-" x 50 . "\n");

    my $exp = Expect->new();
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=$timeout $username\@$host")) {
        log_print("  ERROR: Failed to spawn SSH to $host\n\n");
        $overall_status = 1;
        next;
    }

    my $login_ok = 0;
    $exp->expect($timeout,
        ['assword:', sub { $exp->send("$password\n"); exp_continue; }],
        ['yes/no',   sub { $exp->send("yes\n");       exp_continue; }],
        ['refused',  sub { }],
        ['#',        sub { $login_ok = 1; }],
        ['>',        sub { $login_ok = 2; }],
        ['timeout',  sub { }],
    );

    unless ($login_ok) {
        log_print("  ERROR: Connection failed or auth error\n\n");
        $overall_status = 1;
        $exp->hard_close();
        next;
    }

    if ($login_ok == 2) {
        $exp->send("enable\n");
        $exp->expect($timeout, ['assword:', sub { $exp->send("$enable_pass\n"); }]);
        $exp->expect($timeout, '#');
    }

    $exp->send("terminal length 0\n");
    $exp->expect($timeout, '#');

    $exp->send("show ntp status\n");
    my $ntp_status = '';
    $exp->expect($timeout, [qr/#/, sub { $ntp_status = $exp->before(); }]);

    $exp->send("show ntp associations\n");
    my $ntp_assoc = '';
    $exp->expect($timeout, [qr/#/, sub { $ntp_assoc = $exp->before(); }]);

    $exp->send("show run | include ntp authentication\n");
    my $ntp_auth = '';
    $exp->expect($timeout, [qr/#/, sub { $ntp_auth = $exp->before(); }]);

    $exp->send("exit\n");
    $exp->soft_close();

    my $synced   = ($ntp_status =~ /Clock is synchronized/i) ? 'YES' : 'NO';
    my $stratum  = ($ntp_status =~ /stratum\s+(\d+)/i)       ? $1   : 'N/A';
    my $offset   = ($ntp_status =~ /offset\s+([\-\d\.]+)/i)  ? $1   : 'N/A';
    my $ref_ip   = ($ntp_status =~ /reference is\s+([\d\.]+)/i) ? $1 : 'unknown';
    my $auth_ena = ($ntp_auth   =~ /ntp authenticate/i)       ? 'YES' : 'NO';

    my @issues;
    push @issues, "NOT SYNCED"                         if $synced ne 'YES';
    push @issues, "stratum $stratum > $max_stratum"   if $stratum ne 'N/A' && $stratum > $max_stratum;
    push @issues, "offset ${offset}ms > ${max_offset}ms" if $offset ne 'N/A' && abs($offset) > $max_offset;
    push @issues, "NTP authentication not enabled"     if $auth_ena ne 'YES';

    my $status = @issues ? "NON-COMPLIANT" : "COMPLIANT";
    $overall_status = 1 if @issues;

    log_print("  Sync:         $synced\n");
    log_print("  Stratum:      $stratum\n");
    log_print("  Offset:       ${offset}ms\n");
    log_print("  Reference:    $ref_ip\n");
    log_print("  NTP Auth:     $auth_ena\n");
    log_print("  Status:       $status\n");
    log_print("  Issues:       " . join("; ", @issues) . "\n") if @issues;
    log_print("\n");
}

log_print("=" x 70 . "\n");
log_print("Audit complete. Overall: " . ($overall_status ? "NON-COMPLIANT" : "ALL COMPLIANT") . "\n");
log_print("=" x 70 . "\n");

close $log_fh if $log_fh;
exit $overall_status;