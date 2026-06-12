```perl
#!/usr/bin/perl
# =============================================================================
# ntp_stratum_audit.pl - NTP Stratum & Drift Compliance Auditor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices and audits NTP stratum levels,
#   reference clock associations, and frequency drift for compliance.
#   Useful for validating NTP hierarchy integrity across a fleet and
#   identifying devices with misconfigured stratum or excessive drift.
#
# Usage:
#   perl ntp_stratum_audit.pl -h 192.168.1.1 -u admin -p password
#   perl ntp_stratum_audit.pl -f devices.txt -u admin -p password -l audit.log
#   perl ntp_stratum_audit.pl -h 10.0.0.1 -u admin -p pass -s 4 -d 200
#
# Options:
#   -h  Single device IP or hostname
#   -f  File containing one device per line (# comments and blanks ignored)
#   -u  SSH username
#   -p  SSH password
#   -l  Optional log file (appended)
#   -s  Max acceptable stratum (default: 5)
#   -d  Max acceptable drift in ppm (default: 500)
#   -t  SSH timeout in seconds (default: 15)
#
# Prerequisites:
#   cpanm Net::SSH::Expect
#
# Tested on: Cisco IOS 15.x, IOS-XE 16.x/17.x
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file);
my $timeout       = 15;
my $max_stratum   = 5;
my $max_drift_ppm = 500;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$device_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'l|log=s'     => \$log_file,
    's|stratum=i' => \$max_stratum,
    'd|drift=i'   => \$max_drift_ppm,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [options]\n";

die "Provide -h <host> or -f <file>\n" unless $host || $device_file;
die "Username required (-u)\n"         unless $username;
die "Password required (-p)\n"         unless $password;

my @devices;
if ($host) {
    @devices = ($host);
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    @devices = map { chomp; $_ } grep { /\S/ && !/^#/ } <$fh>;
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=" x 62);
out("NTP Stratum & Drift Audit  |  $ts");
out(sprintf("Thresholds: stratum <= %d, drift <= +/-%d ppm", $max_stratum, $max_drift_ppm));
out("=" x 62);

my ($pass_count, $fail_count) = (0, 0);

for my $device (@devices) {
    out("\n[$device]");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $device,
            user     => $username,
            password => $password,
            raw_pty  => 1,
            timeout  => $timeout,
        );
    };
    if ($@ || !$ssh) {
        out("  ERROR: Cannot initialize SSH session: " . ($@ || "unknown error"));
        $fail_count++;
        next;
    }

    my $logged_in = eval { $ssh->login() };
    if ($@ || !$logged_in) {
        out("  ERROR: Authentication failed");
        $fail_count++;
        next;
    }

    $ssh->exec("terminal length 0");
    my $ntp_status = $ssh->exec("show ntp status")       // '';
    my $ntp_assoc  = $ssh->exec("show ntp associations")  // '';
    $ssh->close();

    my $sync_state = ($ntp_status =~ /Clock is (\S+)/i)                 ? ucfirst(lc($1)) : 'unknown';
    my $stratum    = ($ntp_status =~ /stratum\s+(\d+)/i)                 ? $1              : 'N/A';
    my $drift      = ($ntp_status =~ /frequency is\s+([\d.+-]+)\s+ppm/i) ? $1              : 'N/A';
    my $ref_clock  = ($ntp_status =~ /reference is\s+(\S+)/i)            ? $1              : 'N/A';
    my $sync_peer  = ($ntp_assoc  =~ /^\*(\d[\d.]+)/m)                   ? $1              : 'none';

    my @issues;
    push @issues, "NOT SYNCHRONIZED"
        if $sync_state !~ /synchronized/i;
    push @issues, "stratum $stratum > max $max_stratum"
        if $stratum ne 'N/A' && $stratum > $max_stratum;
    push @issues, "drift ${drift}ppm exceeds +/-${max_drift_ppm}ppm"
        if $drift ne 'N/A' && abs($drift) > $max_drift_ppm;

    my $verdict = @issues ? 'FAIL' : 'PASS';

    out(sprintf("  %-12s %s  [%s]", "Sync State:", $sync_state, $verdict));
    out(sprintf("  %-12s %s",       "Stratum:",    $stratum));
    out(sprintf("  %-12s %s ppm",   "Drift:",      $drift));
    out(sprintf("  %-12s %s",       "Ref Clock:",  $ref_clock));
    out(sprintf("  %-12s %s",       "Sync Peer:",  $sync_peer));
    out("  ISSUES:      " . join("; ", @issues)) if @issues;

    @issues ? $fail_count++ : $pass_count++;
}

out("\n" . "=" x 62);
out(sprintf("Summary: %d PASSED  |  %d FAILED  |  %d total",
    $pass_count, $fail_count, $pass_count + $fail_count));
out("=" x 62);

close $log_fh if $log_fh;
exit($fail_count > 0 ? 1 : 0);

sub out {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}
```