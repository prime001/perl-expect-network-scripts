```perl
#!/usr/bin/perl
# =============================================================================
# bgp_peer_health.pl - BGP Peer Health Monitor
#
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE routers via SSH and checks
#   BGP peer state. Flags any peer not in Established state, reports
#   prefix counts, and shows session uptime. Useful for post-change
#   verification and routine BGP health audits.
#
# Usage:
#   ./bgp_peer_health.pl -h <host> [-u <user>] [-p <pass>] [-l <logfile>]
#   ./bgp_peer_health.pl -f <hosts.txt> [-u <user>] [-p <pass>] [-l <logfile>]
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#
# Hosts file format (one per line):
#   192.168.1.1
#   router2.example.com
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $hosts_file, $logfile);
my $user     = $ENV{NET_USER} || 'admin';
my $password = $ENV{NET_PASS} || '';
my $timeout  = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$hosts_file,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$logfile,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile]\n";

die "Specify -h <host> or -f <hosts_file>\n" unless $host || $hosts_file;

my @devices;
if ($hosts_file) {
    open(my $fh, '<', $hosts_file) or die "Cannot open $hosts_file: $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log $logfile: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=" x 60);
output("BGP Peer Health Check  $timestamp");
output("=" x 60);

my $total_devices  = 0;
my $total_problems = 0;

for my $device (@devices) {
    $total_devices++;
    output("\n--- Device: $device ---");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password    => $password,
        raw_pty     => 1,
        timeout     => $timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        output("  ERROR: SSH connection failed to $device: $@");
        $total_problems++;
        next;
    }

    # Disable paging
    $ssh->send('terminal length 0');
    $ssh->waitfor('\$\s*#', $timeout);

    $ssh->send('show ip bgp summary');
    my $output = $ssh->waitfor('\$\s*#', $timeout);

    unless (defined $output && length $output) {
        output("  ERROR: No output from 'show ip bgp summary' on $device");
        $total_problems++;
        $ssh->close();
        next;
    }

    my $found_peers = 0;
    my $problem_peers = 0;

    for my $line (split /\n/, $output) {
        # BGP summary peer lines: IP  V  AS  MsgRcvd MsgSent TblVer InQ OutQ Up/Down  State/PfxRcd
        next unless $line =~ /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+(\d)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)/;

        my ($peer, $ver, $asn, $updown, $state) = ($1, $2, $3, $4, $5);
        $found_peers++;

        if ($state =~ /^\d+$/) {
            output(sprintf("  %-18s AS%-8s  Established  uptime=%-12s prefixes=%s", $peer, $asn, $updown, $state));
        } else {
            output(sprintf("  %-18s AS%-8s  *** %-12s uptime=%-12s ***", $peer, $asn, $state, $updown));
            $problem_peers++;
            $total_problems++;
        }
    }

    if ($found_peers == 0) {
        output("  No BGP peers found (BGP may not be configured)");
    } else {
        output("  Summary: $found_peers peer(s), $problem_peers not Established");
    }

    $ssh->send('exit');
    $ssh->close();
}

output("\n" . "=" x 60);
output("Checked $total_devices device(s)  |  Problems found: $total_problems");
output("=" x 60);

close $log_fh if $log_fh;
exit($total_problems ? 1 : 0);

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}
```