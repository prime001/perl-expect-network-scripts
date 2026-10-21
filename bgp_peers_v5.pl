#!/usr/bin/perl
# =============================================================================
# bgp_prefix_monitor.pl - BGP Prefix Limit Monitor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers via SSH and checks each BGP neighbor's
#   received prefix count against its configured maximum-prefix limit. Alerts
#   when a peer is within a configurable threshold of its limit (default 80%).
#   Useful for proactive capacity management before sessions tear down.
#
# Usage:
#   ./bgp_prefix_monitor.pl <host>                       # single device
#   ./bgp_prefix_monitor.pl --file devices.txt           # batch from file
#   ./bgp_prefix_monitor.pl --threshold 90 <host>        # custom alert %
#   ./bgp_prefix_monitor.pl --log /var/log/bgp.log <host>
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH key auth or set BGP_PASS env var for password auth
#   BGP_USER env var (default: admin)
#
# Output columns:
#   NEIGHBOR | STATE | PREFIXES | LIMIT | USAGE% | STATUS
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my $threshold   = 80;
my $log_file    = '';
my $device_file = '';
my $timeout     = 30;

GetOptions(
    'threshold=i' => \$threshold,
    'log=s'       => \$log_file,
    'file=s'      => \$device_file,
    'timeout=i'   => \$timeout,
) or die "Usage: $0 [--threshold N] [--log FILE] [--file DEVLIST] <host>\n";

my $user = $ENV{BGP_USER} || 'admin';
my $pass = $ENV{BGP_PASS} || '';

my @devices;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!";
    @devices = grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
    close $fh;
} elsif (@ARGV) {
    @devices = @ARGV;
} else {
    die "Usage: $0 [--threshold N] [--log FILE] [--file DEVLIST] <host>\n";
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!";
    $log_fh->autoflush(1);
}

sub logprint {
    my ($msg) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    print "[$ts] $msg\n";
    print $log_fh "[$ts] $msg\n" if $log_fh;
}

sub check_device {
    my ($host) = @_;
    logprint("Connecting to $host");

    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        user       => $user,
        password   => $pass || undef,
        raw_pty    => 1,
        timeout    => $timeout,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    eval {
        if ($pass) {
            $ssh->login() or die "Login failed";
        } else {
            $ssh->run_ssh() or die "SSH connection failed";
            $ssh->waitfor('[\$#>]\s*$', 10) or die "No prompt";
        }
    };
    if ($@) {
        logprint("ERROR [$host]: Connection failed - $@");
        return;
    }

    # Disable paging
    $ssh->send('terminal length 0');
    $ssh->waitfor('[#>]\s*$', 5);

    # Pull neighbor summary for state and received prefix counts
    $ssh->send('show ip bgp summary');
    my $summary = $ssh->waitfor('[#>]\s*$', $timeout) // '';

    # Pull prefix limits from running config
    $ssh->send('show run | section router bgp');
    my $bgp_config = $ssh->waitfor('[#>]\s*$', $timeout) // '';

    $ssh->send('exit');

    # Parse neighbor states and received prefix counts from summary output.
    # IOS format: neighbor  V  AS  MsgRcvd  MsgSent  TblVer  InQ  OutQ  Up/Down  State/PfxRcd
    my %peer_data;
    for my $line (split /\n/, $summary) {
        if ($line =~ /^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+)/) {
            my ($neighbor, $state_or_pfx) = ($1, $2);
            if ($state_or_pfx =~ /^\d+$/) {
                $peer_data{$neighbor}{prefixes} = $state_or_pfx;
                $peer_data{$neighbor}{state}    = 'Established';
            } else {
                $peer_data{$neighbor}{prefixes} = 0;
                $peer_data{$neighbor}{state}    = $state_or_pfx;
            }
        }
    }

    # Parse maximum-prefix limits from config.
    # IOS syntax: neighbor x.x.x.x maximum-prefix N [threshold%] [warning-only]
    my %limits;
    while ($bgp_config =~ /neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+maximum-prefix\s+(\d+)/g) {
        $limits{$1} = $2;
    }

    logprint("--- BGP Prefix Report: $host ---");
    logprint(sprintf("%-18s %-13s %8s %8s %7s  %s",
        'NEIGHBOR', 'STATE', 'PREFIXES', 'LIMIT', 'USAGE%', 'STATUS'));
    logprint('-' x 70);

    my $alert_count = 0;
    for my $neighbor (sort keys %peer_data) {
        my $state    = $peer_data{$neighbor}{state};
        my $prefixes = $peer_data{$neighbor}{prefixes};
        my $limit    = $limits{$neighbor} // 'N/A';
        my ($usage, $status);

        if ($limit =~ /^\d+$/ && $state eq 'Established') {
            $usage  = int($prefixes / $limit * 100);
            $status = $usage >= $threshold ? "ALERT (>=${threshold}%)" : 'OK';
            $alert_count++ if $usage >= $threshold;
        } else {
            $usage  = '--';
            $status = $state eq 'Established' ? 'no-limit-cfg' : 'DOWN';
            $alert_count++ if $state ne 'Established';
        }

        logprint(sprintf("%-18s %-13s %8s %8s %7s  %s",
            $neighbor, $state, $prefixes, $limit, $usage, $status));
    }

    logprint("Summary: " . scalar(keys %peer_data) . " peers, $alert_count requiring attention");
}

for my $host (@devices) {
    check_device($host);
    print "\n";
}

close $log_fh if $log_fh;