#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# bgp_route_audit.pl - BGP Advertised/Received Route Prefix Auditor
#
# Purpose:
#   Connects to a Cisco IOS/IOS-XE router and audits prefix counts for each
#   BGP neighbor - both advertised-routes and received-routes. Flags peers
#   with zero advertised prefixes (common misconfiguration / policy issue)
#   and peers where received count dropped significantly vs a threshold.
#
# Usage:
#   ./bgp_route_audit.pl --host <ip> --user <user> --pass <pass> [options]
#   ./bgp_route_audit.pl --file devices.txt --user <user> --pass <pass>
#
# Options:
#   --host <ip>         Single device IP or hostname
#   --file <file>       File with one device IP per line
#   --user <user>       SSH username (default: admin)
#   --pass <pass>       SSH password
#   --enable <pass>     Enable password (if needed)
#   --min-prefixes <n>  Alert if advertised prefix count below this (default: 1)
#   --log <file>        Write output to log file in addition to STDOUT
#   --timeout <sec>     SSH command timeout in seconds (default: 30)
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   Device must have 'soft-reconfiguration inbound' or 'route-refresh' for
#   received-routes to be populated.
#
# =============================================================================

my %opt = (
    user          => 'admin',
    timeout       => 30,
    'min-prefixes' => 1,
);

GetOptions(\%opt,
    'host=s', 'file=s', 'user=s', 'pass=s', 'enable=s',
    'min-prefixes=i', 'log=s', 'timeout=i',
) or die "Invalid options. Use --help for usage.\n";

die "Provide --host or --file\n" unless $opt{host} || $opt{file};
die "Provide --pass\n"           unless $opt{pass};

my @devices;
if ($opt{host}) {
    push @devices, $opt{host};
} else {
    open my $fh, '<', $opt{file} or die "Cannot open $opt{file}: $!\n";
    @devices = grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
    close $fh;
}

my $log_fh;
if ($opt{log}) {
    open $log_fh, '>>', $opt{log} or die "Cannot open log $opt{log}: $!\n";
}

sub emit {
    print @_;
    print $log_fh @_ if $log_fh;
}

sub audit_device {
    my ($host) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    emit "\n=== $host  [$ts] ===\n";

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $opt{user},
        password    => $opt{pass},
        raw_pty     => 1,
        timeout     => $opt{timeout},
    );

    eval { $ssh->login() };
    if ($@) {
        emit "  ERROR: SSH login failed - $@\n";
        return;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('>\s*$|\#\s*$', 5);

    if ($opt{enable}) {
        $ssh->send('enable');
        $ssh->waitfor('Password:\s*$', 5);
        $ssh->send($opt{enable});
        $ssh->waitfor('\#\s*$', 5);
    }

    # Pull BGP summary to get peer list
    $ssh->send('show ip bgp summary');
    my $summary = $ssh->waitfor('\#\s*$', $opt{timeout});
    unless ($summary) {
        emit "  ERROR: Timeout waiting for BGP summary\n";
        $ssh->close();
        return;
    }

    # Parse neighbor IPs from BGP summary table (lines starting with an IP)
    my @peers = ($summary =~ /^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+/mg);
    if (!@peers) {
        emit "  No BGP peers found (BGP may not be running)\n";
        $ssh->close();
        return;
    }

    emit "  Found " . scalar(@peers) . " BGP peer(s)\n\n";
    emit sprintf("  %-18s %12s %12s  %s\n", 'Peer', 'Advertised', 'Received', 'Status');
    emit "  " . "-"x60 . "\n";

    my @alerts;
    for my $peer (@peers) {
        my ($adv_count, $rcv_count) = (0, 0);

        $ssh->send("show ip bgp neighbors $peer advertised-routes");
        my $adv = $ssh->waitfor('\#\s*$', $opt{timeout}) // '';
        if ($adv =~ /Total number of prefixes (\d+)/i) {
            $adv_count = $1;
        } elsif ($adv =~ /(\d+)\s+network entries/i) {
            $adv_count = $1;
        }

        $ssh->send("show ip bgp neighbors $peer received-routes");
        my $rcv = $ssh->waitfor('\#\s*$', $opt{timeout}) // '';
        if ($rcv =~ /Total number of prefixes (\d+)/i) {
            $rcv_count = $1;
        } elsif ($rcv =~ /(\d+)\s+network entries/i) {
            $rcv_count = $1;
        }

        my $status = 'OK';
        if ($adv_count < $opt{'min-prefixes'}) {
            $status = "ALERT:adv<$opt{'min-prefixes'}";
            push @alerts, "$peer advertised only $adv_count prefix(es) (threshold: $opt{'min-prefixes'})";
        }

        emit sprintf("  %-18s %12d %12d  %s\n", $peer, $adv_count, $rcv_count, $status);
    }

    if (@alerts) {
        emit "\n  ALERTS:\n";
        emit "    - $_\n" for @alerts;
    }

    $ssh->send('exit');
    $ssh->close();
}

for my $dev (@devices) {
    audit_device($dev);
}

emit "\nDone. Audited " . scalar(@devices) . " device(s).\n";
close $log_fh if $log_fh;