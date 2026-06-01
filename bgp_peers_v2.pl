```perl
#!/usr/bin/perl
# =============================================================================
# bgp_route_policy.pl - BGP Route Policy and Community Verification Tool
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers and audits BGP route policy by
#   examining received and advertised prefixes per peer, along with community
#   tags, local-pref, MED, and AS-path attributes. Useful for validating
#   inbound/outbound route-map behavior and policy changes.
#
# Usage:
#   ./bgp_route_policy.pl -h <host> -u <user> -p <pass> [-P <peer_ip>] [-l logfile]
#   ./bgp_route_policy.pl -f devices.txt -u <user> -p <pass>
#
# Prerequisites:
#   cpan Expect Getopt::Long
#
# Output:
#   Per-peer prefix count, community summary, anomalies (missing communities,
#   unexpected local-pref, etc.)
#
# Examples:
#   ./bgp_route_policy.pl -h 10.0.0.1 -u admin -p secret -P 203.0.113.5
#   ./bgp_route_policy.pl -f routers.txt -u netops -p pass123 -l /tmp/bgp_audit.log
# =============================================================================

use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $pass, $peer, $device_file, $log_file);
my $timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'P|peer=s'     => \$peer,
    'f|file=s'     => \$device_file,
    'l|log=s'      => \$log_file,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h <host> -u <user> -p <pass> [-P <peer>] [-l logfile]\n";

die "Credentials required: -u <user> -p <pass>\n" unless $user && $pass;
die "Specify -h <host> or -f <file>\n" unless $host || $device_file;

my @hosts = $host ? ($host) : do {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    map { chomp; $_ } grep { /\S/ && !/^#/ } <$fh>;
};

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open logfile $log_file: $!\n";
}

sub log_output {
    my ($msg) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    print "[$ts] $msg\n";
    print $log_fh "[$ts] $msg\n" if $log_fh;
}

sub audit_bgp_policy {
    my ($device) = @_;
    log_output("=== Connecting to $device ===");

    my $exp = Expect->new;
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${user}\@${device}")) {
        log_output("ERROR: Failed to spawn SSH for $device");
        return;
    }

    my $logged_in = 0;
    $exp->expect($timeout,
        [ qr/[Pp]assword:/,      sub { $exp->send("$pass\n"); exp_continue; } ],
        [ qr/[>#]/,              sub { $logged_in = 1; } ],
        [ qr/Connection refused/, sub { log_output("ERROR: Connection refused to $device"); } ],
        [ qr/No route to host/,   sub { log_output("ERROR: No route to $device"); } ],
        [ timeout => sub { log_output("ERROR: Timeout connecting to $device"); } ],
    );

    unless ($logged_in) {
        $exp->soft_close;
        return;
    }

    $exp->send("terminal length 0\n");
    $exp->expect(10, qr/[>#]/);

    # Get BGP summary to find peers if none specified
    $exp->send("show ip bgp summary\n");
    $exp->expect($timeout, qr/[>#]/);
    my $summary = $exp->before();

    my @peers_to_check;
    if ($peer) {
        @peers_to_check = ($peer);
    } else {
        # Parse established peers from summary
        while ($summary =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)/mg) {
            push @peers_to_check, $1 if $2 > 0;  # only established peers (prefix count > 0)
        }
    }

    if (!@peers_to_check) {
        log_output("$device: No established BGP peers found");
        $exp->send("exit\n");
        $exp->soft_close;
        return;
    }

    for my $p (@peers_to_check) {
        log_output("$device: Auditing peer $p");

        $exp->send("show ip bgp neighbors $p received-routes | include Network|Community|localpref|metric\n");
        $exp->expect($timeout, qr/[>#]/);
        my $received = $exp->before();

        $exp->send("show ip bgp neighbors $p advertised-routes | include Network|Community|localpref|metric\n");
        $exp->expect($timeout, qr/[>#]/);
        my $advertised = $exp->before();

        my $rx_count  = () = $received  =~ /^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/mg;
        my $adv_count = () = $advertised =~ /^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/mg;

        log_output("$device peer $p: received=$rx_count prefixes, advertised=$adv_count prefixes");

        my %communities;
        while ($received =~ /Community:\s*([^\n]+)/g) {
            $communities{$_}++ for split /\s+/, $1;
        }
        if (%communities) {
            my $comm_str = join(", ", map { "$_($communities{$_})" } sort keys %communities);
            log_output("$device peer $p: communities seen: $comm_str");
        } else {
            log_output("$device peer $p: WARNING - no BGP communities on received routes");
        }

        # Flag if received but nothing advertised (possible outbound policy blocking all)
        if ($rx_count > 0 && $adv_count == 0) {
            log_output("$device peer $p: ALERT - receiving routes but advertising none (check outbound route-map)");
        }
    }

    $exp->send("exit\n");
    $exp->soft_close;
}

audit_bgp_policy($_) for @hosts;
close $log_fh if $log_fh;
log_output("Audit complete.");
```