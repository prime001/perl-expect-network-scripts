```perl
#!/usr/bin/perl
# =============================================================================
# bgp_prefix_monitor.pl - BGP Prefix Count Threshold Monitor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers and audits BGP neighbor prefix counts
#   against configurable high/low thresholds. Flags peers with prefix counts
#   outside expected ranges -- useful for detecting route leaks, peer failures,
#   or misconfigured filters before they impact traffic.
#
# Usage:
#   ./bgp_prefix_monitor.pl -h <host> [-u <user>] [-p <pass>] [-l <logfile>]
#                            [-H <high_thresh>] [-L <low_thresh>]
#   ./bgp_prefix_monitor.pl -f <device_file> [-u <user>] [-p <pass>] [-l <logfile>]
#
#   Device file format (one per line): <ip_or_hostname>
#   Example: ./bgp_prefix_monitor.pl -f routers.txt -u admin -p secret -H 800000 -L 100
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH key auth recommended; password auth supported via -p flag
#
# Output:
#   STDOUT + optional log file. Exit code 1 if any threshold violations found.
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $logfile);
my $high_thresh = 900000;
my $low_thresh  = 1;

GetOptions(
    'h=s' => \$host,
    'f=s' => \$device_file,
    'u=s' => \$username,
    'p=s' => \$password,
    'l=s' => \$logfile,
    'H=i' => \$high_thresh,
    'L=i' => \$low_thresh,
) or die "Usage: $0 -h <host>|-f <file> [-u user] [-p pass] [-l logfile] [-H high] [-L low]\n";

die "Specify -h <host> or -f <file>\n" unless $host || $device_file;

$username //= $ENV{NET_USER} // 'admin';

my @devices = $host ? ($host) : do {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
};

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or warn "Cannot open logfile $logfile: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $violations = 0;

sub log_line {
    my $line = shift;
    print $line, "\n";
    print $log_fh $line, "\n" if $log_fh;
}

log_line("=" x 70);
log_line("BGP Prefix Threshold Audit  [$timestamp]");
log_line("Thresholds: LOW < $low_thresh  |  HIGH > $high_thresh");
log_line("=" x 70);

for my $device (@devices) {
    log_line("\n>>> Device: $device");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $device,
            user        => $username,
            defined $password ? (password => $password) : (),
            raw_pty     => 1,
            timeout     => 20,
        );
    };
    if ($@ || !$ssh) {
        log_line("  ERROR: SSH object creation failed for $device: $@");
        $violations++;
        next;
    }

    my $login_out = eval { $ssh->login() };
    if ($@ || !defined $login_out) {
        log_line("  ERROR: Login failed for $device (auth error or timeout)");
        $violations++;
        next;
    }

    $ssh->exec("terminal length 0");

    my $output = $ssh->exec("show ip bgp summary");
    unless (defined $output && $output =~ /Neighbor/i) {
        log_line("  WARNING: No BGP summary output received (BGP may not be running)");
        $ssh->close();
        next;
    }

    my $found_peer = 0;
    for my $line (split /\n/, $output) {
        next unless $line =~ /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+)/;
        my ($neighbor, $pfx_field) = ($1, $2);
        $found_peer = 1;

        if ($pfx_field !~ /^\d+$/) {
            log_line(sprintf("  %-18s  state=%-10s  (not established)", $neighbor, $pfx_field));
            $violations++;
            next;
        }

        my $pfx_count = int($pfx_field);
        my $status = "OK";
        if ($pfx_count > $high_thresh) {
            $status = "ALERT:HIGH";
            $violations++;
        } elsif ($pfx_count < $low_thresh) {
            $status = "ALERT:LOW";
            $violations++;
        }
        log_line(sprintf("  %-18s  prefixes=%-8d  %s", $neighbor, $pfx_count, $status));
    }

    log_line("  (no established BGP neighbors found)") unless $found_peer;
    $ssh->close();
}

log_line("\n" . "=" x 70);
log_line("Audit complete. Violations: $violations");
log_line("=" x 70);

close $log_fh if $log_fh;
exit($violations ? 1 : 0);
```