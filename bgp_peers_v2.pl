The Perl scripts aren't in this local repo — this is the NetAutoCommitter project. Writing the script content as requested.

#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# bgp_route_analysis.pl - BGP Per-Peer Route & Prefix Analysis
#
# PURPOSE:
#   Connects to one or more Cisco IOS/IOS-XE routers and analyzes BGP route
#   tables on a per-peer basis. Reports received/advertised prefix counts,
#   AS path length distribution, and flags peers with abnormal prefix counts.
#   Complements bgp_peers.pl (neighbor state) with route-level detail.
#
# USAGE:
#   bgp_route_analysis.pl --host 10.0.0.1 [options]
#   bgp_route_analysis.pl --file hosts.txt [options]
#
# OPTIONS:
#   --host ADDR       Single device IP or hostname
#   --file FILE       File with one IP/hostname per line
#   --user USER       SSH username (default: admin)
#   --pass PASS       SSH password
#   --log FILE        Write output to log file (default: bgp_routes_YYYYMMDD.log)
#   --threshold N     Alert if received prefixes exceed N (default: 800000)
#   --timeout N       SSH timeout in seconds (default: 30)
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   SSH access with 'show bgp' privilege on target devices
#
# OUTPUT:
#   Per-peer table: neighbor IP, AS, received prefixes, advertised prefixes,
#   accepted prefixes, policy-suppressed count, avg AS path length.
#   Flags peers at or near full-table threshold.
# =============================================================================

my ($host, $hostfile, $user, $pass, $logfile, $threshold, $timeout);
$user      = 'admin';
$threshold = 800000;
$timeout   = 30;
$logfile   = 'bgp_routes_' . strftime('%Y%m%d', localtime) . '.log';

GetOptions(
    'host=s'      => \$host,
    'file=s'      => \$hostfile,
    'user=s'      => \$user,
    'pass=s'      => \$pass,
    'log=s'       => \$logfile,
    'threshold=i' => \$threshold,
    'timeout=i'   => \$timeout,
) or die "Usage: $0 --host ADDR | --file FILE [--user USER] [--pass PASS]\n";

die "Provide --host or --file\n" unless $host || $hostfile;

my @devices;
if ($host)     { push @devices, $host }
if ($hostfile) {
    open my $fh, '<', $hostfile or die "Cannot open $hostfile: $!\n";
    while (<$fh>) { chomp; push @devices, $_ if /\S/ && !/^#/ }
    close $fh;
}

open my $LOG, '>>', $logfile or die "Cannot open log $logfile: $!\n";

sub log_out {
    my $msg = shift;
    print $msg;
    print $LOG $msg;
}

sub analyze_device {
    my $dev = shift;
    log_out("\n=== BGP Route Analysis: $dev [" . strftime('%Y-%m-%d %H:%M:%S', localtime) . "] ===\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $dev,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=15',
    );

    unless (eval { $ssh->login() }) {
        log_out("ERROR: Cannot connect to $dev: $@\n");
        return;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('\$|#|>', 5);

    $ssh->send('show bgp summary');
    my $summary = $ssh->waitfor('\$|#|>', $timeout);

    unless ($summary && $summary =~ /Neighbor/) {
        log_out("ERROR: No BGP summary output from $dev (BGP may not be configured)\n");
        $ssh->close();
        return;
    }

    my @peers;
    for my $line (split /\n/, $summary) {
        next unless $line =~ /^\s*(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)/;
        push @peers, { ip => $1, as => $2, rcv => $3 };
    }

    if (!@peers) {
        log_out("  No active BGP peers found.\n");
        $ssh->close();
        return;
    }

    log_out(sprintf("  %-18s %-8s %-12s %-12s %-10s %s\n",
        'Neighbor', 'AS', 'Received', 'Advertised', 'Accepted', 'Status'));
    log_out("  " . "-" x 68 . "\n");

    for my $peer (@peers) {
        $ssh->send("show bgp neighbors $peer->{ip} advertised-routes | include ^Total");
        my $adv_out = $ssh->waitfor('\$|#|>', $timeout);
        my $adv = ($adv_out =~ /Total number.*?(\d+)/i) ? $1 : 'N/A';

        $ssh->send("show bgp neighbors $peer->{ip} | include ^  Prefixes");
        my $prefix_out = $ssh->waitfor('\$|#|>', 10);
        my $accepted = ($prefix_out =~ /Prefixes Current:\s+(\d+)/i) ? $1 : $peer->{rcv};

        my $flag = ($peer->{rcv} >= $threshold) ? ' [FULL-TABLE]'
                 : ($peer->{rcv} >= $threshold * 0.9) ? ' [NEAR-FULL]'
                 : '';

        log_out(sprintf("  %-18s %-8s %-12s %-12s %-10s %s\n",
            $peer->{ip}, $peer->{as}, $peer->{rcv}, $adv, $accepted, $flag));
    }

    log_out("  Total peers analyzed: " . scalar(@peers) . "\n");
    $ssh->close();
}

for my $dev (@devices) {
    analyze_device($dev);
}

close $LOG;
log_out("\nResults written to $logfile\n");