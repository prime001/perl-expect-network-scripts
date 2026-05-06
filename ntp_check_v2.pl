#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# ntp_compliance_check.pl - NTP Stratum & Offset Compliance Auditor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices and validates NTP synchronization
#   against policy thresholds: max stratum level and max clock offset (ms).
#   Generates a pass/fail compliance report across a device fleet.
#
# Usage:
#   Single device:  perl ntp_compliance_check.pl -h 192.168.1.1 -u admin -p secret
#   Device list:    perl ntp_compliance_check.pl -f devices.txt -u admin -p secret
#   Custom limits:  perl ntp_compliance_check.pl -f devices.txt -u admin -p secret \
#                     --max-stratum 3 --max-offset 50
#
# Prerequisites:
#   cpan Net::SSH::Expect
#
# Device list format (devices.txt): one IP or hostname per line, # for comments
# =============================================================================

my ($host, $file, $user, $pass, $logfile);
my $max_stratum = 4;
my $max_offset  = 100;
my $timeout     = 15;

GetOptions(
    'h|host=s'       => \$host,
    'f|file=s'       => \$file,
    'u|user=s'       => \$user,
    'p|pass=s'       => \$pass,
    'l|log=s'        => \$logfile,
    'max-stratum=i'  => \$max_stratum,
    'max-offset=f'   => \$max_offset,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [--max-stratum N] [--max-offset MS]\n";

die "Provide -h HOST or -f FILE\n" unless $host || $file;
die "Provide -u USER and -p PASS\n" unless $user && $pass;

my @devices = $host ? ($host) : do {
    open(my $fh, '<', $file) or die "Cannot open $file: $!\n";
    grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
};

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or warn "Cannot open log $logfile: $!\n";
}

sub output {
    print @_;
    print $log_fh @_ if $log_fh;
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=" x 70 . "\n");
output("NTP Compliance Audit  |  $ts\n");
output(sprintf("Policy: max_stratum=%d  max_offset=%.1fms\n", $max_stratum, $max_offset));
output("=" x 70 . "\n\n");

my ($pass_count, $fail_count) = (0, 0);

for my $dev (@devices) {
    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $dev,
            user        => $user,
            password    => $pass,
            raw_pty     => 1,
            timeout     => $timeout,
        );
    };
    if ($@ || !$ssh) {
        output("[$dev] ERROR: SSH init failed - $@\n");
        $fail_count++;
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !$login) {
        output("[$dev] ERROR: Authentication failed\n");
        $fail_count++;
        next;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#', 5);

    $ssh->send("show ntp status");
    my $ntp_status = $ssh->waitfor('\$|#', 10) // '';

    $ssh->send("show ntp associations");
    my $ntp_assoc = $ssh->waitfor('\$|#', 10) // '';

    $ssh->send("exit");

    my %result = (synced => 0, stratum => 'N/A', offset => 'N/A', ref => 'N/A');

    if ($ntp_status =~ /Clock is synchronized/i) {
        $result{synced} = 1;
    }
    if ($ntp_status =~ /stratum\s+(\d+)/i) {
        $result{stratum} = $1;
    }
    if ($ntp_status =~ /offset\s+([+-]?\d+\.\d+)/i) {
        $result{offset} = $1;
    }
    if ($ntp_status =~ /reference is\s+(\S+)/i) {
        $result{ref} = $1;
    }

    my @issues;
    push @issues, "NOT SYNCHRONIZED" unless $result{synced};
    push @issues, "stratum $result{stratum} > max $max_stratum"
        if $result{stratum} =~ /^\d+$/ && $result{stratum} > $max_stratum;
    push @issues, sprintf("offset %.1fms > max %.1fms", $result{offset}, $max_offset)
        if $result{offset} =~ /^[+-]?\d/ && abs($result{offset}) > $max_offset;

    my $status = @issues ? "FAIL" : "PASS";
    $status eq 'PASS' ? $pass_count++ : $fail_count++;

    output(sprintf("[%s] %-4s | stratum=%-3s offset=%-10s ref=%-15s",
        $dev, $status, $result{stratum}, $result{offset}, $result{ref}));
    output(@issues ? " | " . join(", ", @issues) : "");
    output("\n");
}

output("\n" . "-" x 70 . "\n");
output(sprintf("Summary: %d PASS  %d FAIL  %d total\n",
    $pass_count, $fail_count, $pass_count + $fail_count));
output("=" x 70 . "\n");

close($log_fh) if $log_fh;
exit($fail_count ? 1 : 0);