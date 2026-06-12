The user wants the script content as direct output. Here it is:

#!/usr/bin/perl
#
# syslog_analyzer.pl - Cisco IOS Syslog Severity Analyzer
#
# Purpose:
#   SSH into one or more Cisco IOS devices, retrieve the in-memory syslog
#   buffer (show logging), categorize every message by RFC 5424 / Cisco
#   severity level (0-EMERG through 7-DEBUG), and produce a structured
#   report with per-severity counts plus a full listing of all events at
#   ERROR level or above -- the entries most likely to warrant action.
#
# Usage:
#   perl syslog_analyzer.pl <host|hostfile> <user> <pass> [--logfile=FILE]
#
# Arguments:
#   host|hostfile  Single IP/hostname, or a file containing one per line
#                  (lines starting with # are treated as comments)
#   user           SSH username
#   pass           SSH password
#   --logfile      Optional path; output is written to both STDOUT and file
#
# Prerequisites:
#   cpan Net::SSH::Expect
#
# Examples:
#   perl syslog_analyzer.pl 192.168.1.1  admin cisco123
#   perl syslog_analyzer.pl routers.txt  admin cisco123 --logfile=sev_report.txt

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my $logfile = '';
GetOptions('logfile=s' => \$logfile);

my ($target, $username, $password) = @ARGV;
die "Usage: $0 <host|hostfile> <user> <pass> [--logfile=FILE]\n"
    unless $target && $username && $password;

my %SEV_NAME = (
    0 => 'EMERGENCY', 1 => 'ALERT',  2 => 'CRITICAL', 3 => 'ERROR',
    4 => 'WARNING',   5 => 'NOTICE', 6 => 'INFO',      7 => 'DEBUG',
);

my @hosts;
if (-f $target) {
    open(my $fh, '<', $target) or die "Cannot open '$target': $!\n";
    @hosts = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
} else {
    @hosts = ($target);
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>', $logfile) or die "Cannot open logfile '$logfile': $!\n";
}

sub out {
    my $msg = shift;
    print $msg;
    print {$log_fh} $msg if $log_fh;
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
out("=" x 68 . "\n");
out("Cisco Syslog Severity Report  --  $ts\n");
out("=" x 68 . "\n\n");

for my $host (@hosts) {
    out("Host: $host\n");
    out("-" x 52 . "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $host,
            user     => $username,
            password => $password,
            raw_pty  => 1,
            timeout  => 15,
        );
    };
    if ($@ || !$ssh) {
        out("  FAIL: Could not create SSH session -- $@\n\n");
        next;
    }

    my $logged_in = eval { $ssh->login() };
    if ($@ || !$logged_in) {
        out("  FAIL: Authentication failed or connection refused\n\n");
        next;
    }

    eval { $ssh->exec("terminal length 0") };

    my $raw = eval { $ssh->exec("show logging") };
    if ($@ || !$raw) {
        out("  FAIL: 'show logging' returned no output -- $@\n\n");
        $ssh->close();
        next;
    }

    my (%counts, @flagged);
    $counts{$_} = 0 for keys %SEV_NAME;

    # Cisco syslog line: *timestamp: %FACILITY-SEVERITY-MNEMONIC: message
    while ($raw =~ /^(.*%[A-Z0-9_]+-([0-7])-[A-Z0-9_]+:.+)$/mg) {
        my ($line, $sev) = ($1, $2);
        $counts{$sev}++;
        push @flagged, "    $line" if $sev <= 3;
    }

    my $total = 0;
    $total += ($counts{$_} // 0) for keys %SEV_NAME;

    out(sprintf("  Parsed entries : %d\n\n  Per-severity breakdown:\n", $total));

    for my $s (0 .. 7) {
        my $n   = $counts{$s} // 0;
        my $tag = ($s <= 3 && $n > 0) ? "  <<" : "";
        out(sprintf("    [%d] %-13s  %4d%s\n", $s, $SEV_NAME{$s}, $n, $tag));
    }

    if (@flagged) {
        out("\n  High-severity events (levels 0-3):\n");
        out("$_\n") for @flagged;
    } else {
        out("\n  No high-severity events detected.\n");
    }

    $ssh->close();
    out("\n");
}

close $log_fh if $log_fh;
out("Report complete.\n");