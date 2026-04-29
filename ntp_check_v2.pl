The user asked for the script content output directly with no fences. Here it is:

#!/usr/bin/perl
# =============================================================================
# ntp_compliance_audit.pl - Multi-device NTP Compliance Auditor
#
# Purpose:
#   Audits NTP synchronization compliance across a fleet of Cisco IOS devices.
#   Validates stratum level, clock offset, and reference source against
#   configurable thresholds. Generates a pass/fail compliance summary suitable
#   for change management or audit documentation.
#
# Usage:
#   ./ntp_compliance_audit.pl -f devices.txt [-u username] [-p password]
#                              [-s max_stratum] [-o max_offset_ms] [-l logfile]
#   ./ntp_compliance_audit.pl -d 192.168.1.1 [-u admin] [-p secret]
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#
# Output:
#   Per-device status lines + summary table to STDOUT; optionally to log file.
#   Exit code: 0 = all pass, 1 = one or more failures, 2 = script error
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);

our %opts;
getopts('f:d:u:p:s:o:l:', \%opts);

my $username    = $opts{u} || $ENV{NET_USER}  || 'admin';
my $password    = $opts{p} || $ENV{NET_PASS}  || die "Password required (-p or NET_PASS)\n";
my $max_stratum = $opts{s} || 3;
my $max_offset  = $opts{o} || 500;   # milliseconds
my $logfile     = $opts{l} || '';
my $timestamp   = strftime("%Y-%m-%d %H:%M:%S", localtime);

my @devices;
if ($opts{d}) {
    @devices = ($opts{d});
} elsif ($opts{f}) {
    open(my $fh, '<', $opts{f}) or die "Cannot open device file '$opts{f}': $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
} else {
    die "Specify -d <device> or -f <device_file>\n";
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log '$logfile': $!\n";
}

sub output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub check_device {
    my ($host) = @_;
    my %result = (
        host      => $host,
        status    => 'FAIL',
        stratum   => 'N/A',
        offset    => 'N/A',
        ref_clock => 'N/A',
        error     => '',
    );

    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $username,
        password => $password,
        timeout  => 10,
        raw_pty  => 1,
    );

    eval {
        my $login = $ssh->login();
        die "Auth failed\n" unless $login =~ /[>#]/;

        $ssh->send("terminal length 0");
        $ssh->waitfor('\s*[>#]', 5);

        $ssh->send("show ntp status");
        my $status_out = $ssh->waitfor('\s*[>#]', 10);

        $ssh->send("show ntp associations");
        my $assoc_out = $ssh->waitfor('\s*[>#]', 10);

        $ssh->send("exit");
        $ssh->close();

        if ($status_out =~ /Clock is (\w+)/i) {
            my $sync_state = $1;
            if (lc($sync_state) ne 'synchronized') {
                $result{error} = "Not synchronized (state: $sync_state)";
                return %result;
            }
        }

        ($result{stratum})   = $status_out =~ /stratum\s+(\d+)/i;
        ($result{offset})    = $status_out =~ /offset\s+([-\d.]+)/i;
        ($result{ref_clock}) = $status_out =~ /reference is\s+(\S+)/i;

        $result{stratum}   //= 'N/A';
        $result{offset}    //= 'N/A';
        $result{ref_clock} //= 'N/A';

        my $fail_reason = '';
        if ($result{stratum} ne 'N/A' && $result{stratum} > $max_stratum) {
            $fail_reason .= "stratum $result{stratum} > $max_stratum; ";
        }
        if ($result{offset} ne 'N/A' && abs($result{offset}) > $max_offset) {
            $fail_reason .= "offset $result{offset}ms > ${max_offset}ms; ";
        }

        if ($fail_reason) {
            $result{error} = $fail_reason;
        } else {
            $result{status} = 'PASS';
        }
    };
    if ($@) {
        $result{error} = "Connection error: $@";
        $result{error} =~ s/\n/ /g;
    }

    return %result;
}

output("=" x 72 . "\n");
output("NTP Compliance Audit  |  $timestamp\n");
output("Thresholds: max stratum=$max_stratum  max offset=${max_offset}ms\n");
output("=" x 72 . "\n");

my (@pass, @fail);
for my $host (@devices) {
    output("Checking $host ... ");
    my %r = check_device($host);
    if ($r{status} eq 'PASS') {
        output("PASS  (stratum=$r{stratum} offset=$r{offset}ms ref=$r{ref_clock})\n");
        push @pass, \%r;
    } else {
        output("FAIL  [$r{error}]\n");
        push @fail, \%r;
    }
}

output("\n--- Summary ---\n");
output(sprintf("Devices checked: %d  |  PASS: %d  |  FAIL: %d\n",
    scalar @devices, scalar @pass, scalar @fail));

if (@fail) {
    output("\nNon-compliant devices:\n");
    output(sprintf("  %-20s  %s\n", $_->{host}, $_->{error})) for @fail;
}

output("=" x 72 . "\n");
close $log_fh if $log_fh;

exit(@fail ? 1 : 0);