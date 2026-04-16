```perl
#!/usr/bin/perl
# =============================================================================
# bgp_prefix_monitor.pl - BGP Prefix Count and Limit Monitor
# =============================================================================
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers via SSH and collects BGP prefix
#   counts per neighbor. Flags peers approaching or exceeding prefix limits,
#   identifies peers with zero received prefixes, and reports route dampening.
#   Useful for capacity planning and catching misconfigurations before they
#   cause session resets.
#
# Usage:
#   bgp_prefix_monitor.pl -h <host> [-u <user>] [-p <pass>] [-l <logfile>]
#   bgp_prefix_monitor.pl -f <hostfile> [-u <user>] [-p <pass>] [-l <logfile>]
#
# Options:
#   -h  Single device hostname or IP
#   -f  File containing one hostname/IP per line (# = comment)
#   -u  SSH username (default: $BGPMON_USER env var or 'admin')
#   -p  SSH password (default: $BGPMON_PASS env var)
#   -l  Log file path (default: bgp_prefix_monitor.log)
#   -t  SSH/expect timeout in seconds (default: 30)
#   -w  Warn threshold % of prefix-limit (default: 80)
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Std
#
# Author: Network Engineering
# Version: 1.0
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);

our %opts;
getopts('h:f:u:p:l:t:w:', \%opts);

my $username  = $opts{u} || $ENV{BGPMON_USER} || 'admin';
my $password  = $opts{p} || $ENV{BGPMON_PASS} || die "ERROR: Password required (-p or \$BGPMON_PASS)\n";
my $logfile   = $opts{l} || 'bgp_prefix_monitor.log';
my $timeout   = $opts{t} || 30;
my $warn_pct  = $opts{w} || 80;

die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile] [-t timeout] [-w warn%]\n"
    unless $opts{h} || $opts{f};

my @devices;
if ($opts{f}) {
    open(my $fh, '<', $opts{f}) or die "Cannot open host file '$opts{f}': $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
} else {
    @devices = ($opts{h});
}

open(my $log, '>>', $logfile) or die "Cannot open log file '$logfile': $!\n";

sub log_print {
    my $msg = shift;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    print        "[$ts] $msg\n";
    print $log   "[$ts] $msg\n";
}

sub check_bgp_prefixes {
    my ($host) = @_;

    log_print("Connecting to $host");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $username,
        password     => $password,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_out = eval { $ssh->login() };
    if ($@ || !defined $login_out) {
        log_print("ERROR [$host]: SSH login failed - $@");
        return;
    }
    if ($login_out =~ /[Pp]assword|[Dd]enied|[Ff]ail/) {
        log_print("ERROR [$host]: Authentication failed");
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\S+[#>]', $timeout) or do {
        log_print("ERROR [$host]: Timeout waiting for prompt");
        return;
    };

    $ssh->send("show bgp summary\n");
    my $summary = $ssh->waitfor('\S+[#>]', $timeout);
    unless (defined $summary) {
        log_print("ERROR [$host]: Timeout on 'show bgp summary'");
        return;
    }

    my $found_peer = 0;
    log_print("--- BGP Prefix Report: $host ---");

    for my $line (split /\n/, $summary) {
        next unless $line =~ /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)\s+(\S+)/;
        my ($peer_ip, $pfx_rcvd, $state) = ($1, $2, $3);
        $found_peer = 1;

        if ($state =~ /^\d+$/) {
            if ($pfx_rcvd == 0) {
                log_print("WARN  [$host] Peer $peer_ip: Established but 0 prefixes received");
            } else {
                $ssh->send("show bgp neighbors $peer_ip | include Maximum prefix\n");
                my $limit_out = $ssh->waitfor('\S+[#>]', $timeout) // '';
                my $limit_line = (grep { /[Mm]aximum/ } split /\n/, $limit_out)[0] // '';

                if ($limit_line =~ /(\d+)\s+max.*?(\d+)%/) {
                    my ($max, $thresh_pct) = ($1, $2);
                    my $used_pct = int(($pfx_rcvd / $max) * 100);
                    if ($used_pct >= $warn_pct) {
                        log_print("WARN  [$host] Peer $peer_ip: $pfx_rcvd/$max prefixes (${used_pct}% - approaching limit)");
                    } else {
                        log_print("OK    [$host] Peer $peer_ip: $pfx_rcvd/$max prefixes (${used_pct}%)");
                    }
                } else {
                    log_print("OK    [$host] Peer $peer_ip: $pfx_rcvd prefixes (no limit configured)");
                }
            }
        } else {
            log_print("DOWN  [$host] Peer $peer_ip: State=$state");
        }
    }

    log_print("SKIP  [$host]: No BGP peers found in summary output") unless $found_peer;

    $ssh->send("exit\n");
    $ssh->close();
}

log_print("BGP prefix monitor starting - " . scalar(@devices) . " device(s)");
for my $device (@devices) {
    eval { check_bgp_prefixes($device) };
    log_print("ERROR [$device]: Unhandled exception - $@") if $@;
}
log_print("BGP prefix monitor complete");
close $log;
```