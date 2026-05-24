The script is ready — here's the complete content to write to `109_ntp_compliance_audit.pl`:

```perl
#!/usr/bin/perl
# =============================================================================
# ntp_compliance_audit.pl - NTP Policy Compliance Auditor
#
# Purpose:
#   Audits NTP configuration across multiple network devices against a defined
#   policy: approved source IPs, maximum stratum, and acceptable clock offset.
#   Produces a PASS/FAIL compliance summary suitable for audit reports.
#
# Usage:
#   perl ntp_compliance_audit.pl -f devices.txt [-l audit.log] [-s sources.txt]
#   perl ntp_compliance_audit.pl -d 10.0.0.1 [-l audit.log]
#
#   devices.txt format:  ip username password
#   sources.txt format:  one approved NTP server IP per line
#
# Options:
#   -f <file>     File containing device list
#   -d <ip>       Single device IP (prompts for credentials)
#   -l <file>     Log file path (default: ntp_audit_YYYYMMDD.log)
#   -s <file>     Approved NTP sources file (default: warn if not provided)
#   -m <stratum>  Maximum allowed stratum (default: 3)
#   -o <ms>       Maximum allowed offset in ms (default: 500)
#   -t <sec>      SSH timeout (default: 15)
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   Cisco IOS/IOS-XE devices (adjust prompts for other vendors)
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);

my %opts;
getopts('f:d:l:s:m:o:t:', \%opts);

my $MAX_STRATUM   = $opts{m} || 3;
my $MAX_OFFSET_MS = $opts{o} || 500;
my $TIMEOUT       = $opts{t} || 15;
my $timestamp     = strftime("%Y%m%d_%H%M%S", localtime);
my $logfile       = $opts{l} || "ntp_audit_${timestamp}.log";

die "Usage: $0 -f devices.txt | -d ip [-l logfile] [-s approved_sources.txt]\n"
    unless $opts{f} || $opts{d};

open(my $LOG, '>>', $logfile) or die "Cannot open log $logfile: $!";
sub log_out {
    my $msg = shift;
    print $msg;
    print $LOG $msg;
}

my %approved_sources;
if ($opts{s} && -f $opts{s}) {
    open(my $sf, '<', $opts{s}) or die "Cannot open sources file: $!";
    while (<$sf>) {
        chomp;
        s/#.*//; s/^\s+|\s+$//g;
        $approved_sources{$_} = 1 if $_;
    }
    close $sf;
}

my @devices;
if ($opts{d}) {
    print "Username: "; chomp(my $u = <STDIN>);
    print "Password: "; system("stty -echo"); chomp(my $p = <STDIN>); system("stty echo"); print "\n";
    push @devices, { ip => $opts{d}, user => $u, pass => $p };
} else {
    open(my $df, '<', $opts{f}) or die "Cannot open device file: $!";
    while (<$df>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        next unless $_;
        my ($ip, $user, $pass) = split(/\s+/, $_, 3);
        push @devices, { ip => $ip, user => $user, pass => $pass } if $ip && $user;
    }
    close $df;
}

my ($pass_count, $fail_count) = (0, 0);
log_out("=" x 70 . "\n");
log_out("NTP Compliance Audit  |  $timestamp\n");
log_out("Policy: stratum<=$MAX_STRATUM, offset<=${MAX_OFFSET_MS}ms" .
        (keys %approved_sources ? ", approved-sources enforced" : ", no source policy") . "\n");
log_out("=" x 70 . "\n\n");

for my $dev (@devices) {
    my $ip   = $dev->{ip};
    my @failures;

    log_out("--- $ip ---\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $ip,
            user        => $dev->{user},
            password    => $dev->{pass},
            raw_pty     => 1,
            timeout     => $TIMEOUT,
        );
    };
    if ($@ || !$ssh) {
        log_out("  [ERROR] SSH init failed: $@\n\n");
        $fail_count++;
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !$login) {
        log_out("  [ERROR] Login failed (auth error or timeout)\n\n");
        $fail_count++;
        next;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$\s*$|#\s*$', 5);

    $ssh->send("show ntp status");
    my $ntp_status = $ssh->waitfor('#\s*$', 10) // '';

    $ssh->send("show ntp associations detail");
    my $ntp_assoc = $ssh->waitfor('#\s*$', 10) // '';

    $ssh->send("exit");

    if ($ntp_status =~ /Clock is unsynchronized/i) {
        push @failures, "Clock is UNSYNCHRONIZED";
    }

    if ($ntp_status =~ /stratum\s+(\d+)/i) {
        my $stratum = $1;
        log_out("  Stratum  : $stratum\n");
        push @failures, "Stratum $stratum exceeds max $MAX_STRATUM" if $stratum > $MAX_STRATUM;
    } else {
        push @failures, "Could not determine stratum";
    }

    if ($ntp_status =~ /offset\s+([-\d.]+)\s*ms/i || $ntp_status =~ /offset\s+([-\d.]+)/i) {
        my $offset = abs($1);
        $offset *= 1000 if $offset < 10 && $ntp_status !~ /ms/i;
        log_out(sprintf("  Offset   : %.2f ms\n", $offset));
        push @failures, sprintf("Offset %.2fms exceeds max ${MAX_OFFSET_MS}ms", $offset)
            if $offset > $MAX_OFFSET_MS;
    }

    my @active_sources;
    while ($ntp_assoc =~ /address\s+([\d.]+)/gi) {
        push @active_sources, $1;
    }
    if (!@active_sources && $ntp_status =~ /reference is\s+([\d.]+)/i) {
        push @active_sources, $1;
    }

    if (@active_sources) {
        log_out("  Sources  : " . join(", ", @active_sources) . "\n");
        if (%approved_sources) {
            for my $src (@active_sources) {
                push @failures, "Unapproved NTP source: $src"
                    unless $approved_sources{$src};
            }
        }
    } else {
        log_out("  Sources  : (none detected)\n");
        push @failures, "No active NTP sources found" unless grep { /UNSYNCHRONIZED/i } @failures;
    }

    if (@failures) {
        log_out("  Result   : FAIL\n");
        log_out("  Findings :\n");
        log_out("    - $_\n") for @failures;
        $fail_count++;
    } else {
        log_out("  Result   : PASS\n");
        $pass_count++;
    }
    log_out("\n");
}

log_out("=" x 70 . "\n");
log_out(sprintf("SUMMARY  Pass: %d  Fail: %d  Total: %d\n",
    $pass_count, $fail_count, $pass_count + $fail_count));
log_out("=" x 70 . "\n");
log_out("Log: $logfile\n");
close $LOG;
```

This is `109_ntp_compliance_audit.pl` — distinct from the existing `ntp_check` scripts in that it enforces policy (stratum ceiling, offset threshold, approved-source allowlist) across a fleet and produces a per-device PASS/FAIL compliance report. The existing scripts check NTP state; this one audits against defined standards and flags violations.