#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# bgp_prefix_thresholds.pl - BGP Prefix Count Threshold Monitor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers and checks BGP neighbor prefix counts
#   against their configured max-prefix limits. Alerts when any peer is using
#   80%+ of its allowed prefixes or when peers are not in Established state.
#   Useful for capacity planning and catching runaway route leaks early.
#
# Usage:
#   Single device:  ./bgp_prefix_thresholds.pl -h 10.0.0.1 -u admin -p secret
#   Device file:    ./bgp_prefix_thresholds.pl -f devices.txt -u admin -p secret
#   With log:       ./bgp_prefix_thresholds.pl -h 10.0.0.1 -u admin -p secret -l /var/log/bgp_thresh.log
#   Custom AS:      ./bgp_prefix_thresholds.pl -h 10.0.0.1 -u admin -p secret -a 65001
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to target device (key auth recommended over password)
#
# Device file format: one IP or hostname per line, lines starting with # ignored
# =============================================================================

my ($host, $user, $pass, $device_file, $log_file, $local_as);
my $warn_pct = 80;
my $timeout  = 30;

GetOptions(
    'h|host=s'    => \$host,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'f|file=s'    => \$device_file,
    'l|log=s'     => \$log_file,
    'a|as=s'      => \$local_as,
    'w|warn=i'    => \$warn_pct,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h HOST -u USER -p PASS [-l LOGFILE] [-w WARN_PCT]\n";

die "Provide -h HOST or -f FILE\n" unless $host || $device_file;
die "Provide -u USER\n" unless $user;
die "Provide -p PASS\n" unless $pass;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or warn "Cannot open log $log_file: $!\n";
}

sub log_out {
    my $msg = shift;
    my $ts  = strftime("%Y-%m-%d %H:%M:%S", localtime);
    print "[$ts] $msg\n";
    print $log_fh "[$ts] $msg\n" if $log_fh;
}

sub check_device {
    my $dev = shift;
    log_out("=== Checking $dev ===");

    my $ssh = Net::SSH::Expect->new(
        host        => $dev,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    eval { $ssh->login() };
    if ($@) {
        log_out("ERROR $dev: SSH/auth failed - $@");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\#\s*$', 5);

    my $as = $local_as;
    unless ($as) {
        $ssh->send("show bgp summary | include BGP router");
        my $out = $ssh->waitfor('\#\s*$', 10);
        ($as) = $out =~ /local AS number (\d+)/i;
        $as //= 'unknown';
    }

    log_out("Device: $dev  Local AS: $as");

    $ssh->send("show bgp ipv4 unicast neighbors | include BGP neighbor|prefixes|state");
    my $raw = $ssh->waitfor('\#\s*$', 15);

    my ($current_peer, $state, $received, $max);
    my $alert_count = 0;

    for my $line (split /\n/, $raw) {
        if ($line =~ /BGP neighbor is (\S+)/) {
            if ($current_peer && $state) {
                report_peer($dev, $current_peer, $state, $received, $max, \$alert_count);
            }
            $current_peer = $1;
            $state = $received = $max = undef;
        }
        $state    = $1 if $line =~ /BGP state = (\w+)/i;
        $received = $1 if $line =~ /(\d+) accepted prefix/i;
        $max      = $1 if $line =~ /maximum limit (\d+)/i;
    }
    report_peer($dev, $current_peer, $state, $received, $max, \$alert_count) if $current_peer && $state;

    log_out("$dev summary: $alert_count peer(s) need attention");
    $ssh->send("exit");
    $ssh->close();
}

sub report_peer {
    my ($dev, $peer, $state, $rcv, $max, $alerts) = @_;
    $rcv //= 0;
    $state //= 'Unknown';

    if ($state ne 'Established') {
        log_out("  ALERT $peer state=$state (not established)");
        $$alerts++;
        return;
    }

    if ($max && $max > 0) {
        my $pct = int(($rcv / $max) * 100);
        if ($pct >= $warn_pct) {
            log_out("  WARN  $peer Established rcv=$rcv max=$max usage=${pct}%");
            $$alerts++;
        } else {
            log_out("  OK    $peer Established rcv=$rcv max=$max usage=${pct}%");
        }
    } else {
        log_out("  OK    $peer Established rcv=$rcv (no max-prefix configured)");
    }
}

check_device($_) for @devices;
close $log_fh if $log_fh;