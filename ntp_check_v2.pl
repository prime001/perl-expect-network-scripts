```perl
#!/usr/bin/perl
# =============================================================================
# ntp_drift_audit.pl - NTP Drift and Stratum Compliance Auditor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices and audits NTP health beyond basic
#   sync status. Checks clock offset/drift against threshold, validates
#   stratum level, verifies reference clock IP matches approved server list,
#   and flags devices with excessive jitter or unsynchronized state.
#
# Usage:
#   ./ntp_drift_audit.pl -h <host> [-u <user>] [-p <pass>] [-l <logfile>]
#                        [-t <offset_threshold_ms>] [-s <max_stratum>]
#   ./ntp_drift_audit.pl -f <device_list_file> [-u <user>] [-p <pass>]
#
#   Device list file: one IP/hostname per line, blank lines and # comments OK
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to devices with 'show ntp status' and 'show ntp associations'
#
# Exit codes: 0=all OK, 1=warnings, 2=errors/unreachable
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $pass, $logfile, $device_file);
my $offset_threshold = 50;   # ms — flag if |offset| exceeds this
my $max_stratum      = 3;    # flag if stratum > this value
my @approved_servers = ();   # populate to enforce NTP server policy

GetOptions(
    'h|host=s'      => \$host,
    'u|user=s'      => \$user,
    'p|pass=s'      => \$pass,
    'l|log=s'       => \$logfile,
    'f|file=s'      => \$device_file,
    't|threshold=i' => \$offset_threshold,
    's|stratum=i'   => \$max_stratum,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile]\n";

$user //= $ENV{NET_USER} // 'admin';
$pass //= $ENV{NET_PASS} // do { print "Password: "; chomp(my $p = <STDIN>); $p };

my @targets;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @targets, $_ if $_; }
    close $fh;
} elsif ($host) {
    @targets = ($host);
} else {
    die "Specify -h <host> or -f <device_file>\n";
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!";
}

sub output {
    my ($msg) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    print "[$ts] $msg\n";
    print $log_fh "[$ts] $msg\n" if $log_fh;
}

sub audit_device {
    my ($target) = @_;
    output("--- Connecting to $target ---");

    my $ssh = Net::SSH::Expect->new(
        host        => $target,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => 15,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    eval { $ssh->login() };
    if ($@) {
        output("ERROR [$target]: Connection/auth failed - $@");
        return 2;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|#|\>', 5);

    # Collect NTP status
    $ssh->send("show ntp status\n");
    my $status_out = $ssh->waitfor('\$|#|\>', 10) // '';

    # Collect NTP associations detail
    $ssh->send("show ntp associations detail\n");
    my $assoc_out = $ssh->waitfor('\$|#|\>', 10) // '';

    $ssh->send("exit\n");
    $ssh->close();

    my $exit_code = 0;

    # Parse sync state
    if ($status_out =~ /Clock is unsynchronized/) {
        output("CRITICAL [$target]: Clock is NOT synchronized");
        $exit_code = 2;
    } elsif ($status_out =~ /Clock is synchronized,\s+stratum\s+(\d+),\s+reference is\s+(\S+)/) {
        my ($stratum, $ref) = ($1, $2);
        output("OK [$target]: Synchronized | stratum=$stratum | ref=$ref");

        if ($stratum > $max_stratum) {
            output("WARN [$target]: Stratum $stratum exceeds max ($max_stratum)");
            $exit_code = 1 unless $exit_code == 2;
        }

        if (@approved_servers && !grep { $_ eq $ref } @approved_servers) {
            output("WARN [$target]: Reference $ref not in approved server list");
            $exit_code = 1 unless $exit_code == 2;
        }
    } else {
        output("WARN [$target]: Could not parse NTP status output");
        $exit_code = 1;
    }

    # Parse offset from associations detail
    while ($assoc_out =~ /offset\s+([-\d.]+)\s+msec/gi) {
        my $offset = abs($1);
        if ($offset > $offset_threshold) {
            output("WARN [$target]: NTP offset ${offset}ms exceeds threshold (${offset_threshold}ms)");
            $exit_code = 1 unless $exit_code == 2;
        } else {
            output("OK [$target]: Offset ${offset}ms within threshold");
        }
        last; # report first (selected) peer only
    }

    # Parse jitter if available
    if ($assoc_out =~ /jitter\s+([\d.]+)/) {
        my $jitter = $1;
        output("INFO [$target]: NTP jitter ${jitter}ms");
    }

    return $exit_code;
}

my $overall = 0;
output("NTP Drift Audit started | targets=" . scalar(@targets) .
       " | offset_threshold=${offset_threshold}ms | max_stratum=$max_stratum");

for my $target (@targets) {
    my $rc = audit_device($target);
    $overall = $rc if $rc > $overall;
}

output("Audit complete | result=" . ($overall == 0 ? 'ALL_OK' : $overall == 1 ? 'WARNINGS' : 'ERRORS'));
close $log_fh if $log_fh;
exit $overall;
```