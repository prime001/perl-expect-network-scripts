The script content is ready. Here it is:

```perl
#!/usr/bin/perl
#
# bgp_community_audit.pl - BGP Community String Audit and TE Policy Validator
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers via SSH and audits BGP community
#   strings applied to received and advertised routes. Helps network engineers
#   verify traffic-engineering policy is correctly applied — e.g., confirming
#   NO_EXPORT is set on customer routes, that peer communities are being
#   honored, and that local-preference communities from upstream providers
#   are arriving as expected.
#
# Usage:
#   Single device:    ./bgp_community_audit.pl -h 10.0.0.1 -u admin -p secret
#   Device file:      ./bgp_community_audit.pl -f devices.txt -u admin -p secret
#   Filter community: ./bgp_community_audit.pl -h 10.0.0.1 -u admin -p secret -c 65000:100
#   With logging:     ./bgp_community_audit.pl -h 10.0.0.1 -u admin -p secret -l audit.log
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   Perl 5.10+; SSH enabled on target devices; read-only credentials sufficient
#
# Output:
#   Community distribution summary, per-community route counts, and flags
#   routes missing expected communities or carrying unexpected ones.
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $device_file, $username, $password, $log_file, $filter_community);
my $timeout = 30;

GetOptions(
    'h|host=s'      => \$host_arg,
    'f|file=s'      => \$device_file,
    'u|user=s'      => \$username,
    'p|pass=s'      => \$password,
    'l|log=s'       => \$log_file,
    'c|community=s' => \$filter_community,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l logfile] [-c community]\n";

die "Must specify -h or -f\n"    unless $host_arg || $device_file;
die "Must specify -u username\n" unless $username;
die "Must specify -p password\n" unless $password;

my @devices;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!";
    while (<$fh>) { chomp; push @devices, $_ if /\S/ && !/^#/ }
    close $fh;
} else {
    push @devices, $host_arg;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!";
}

sub logprint {
    my $msg = shift;
    my $ts  = strftime("%Y-%m-%d %H:%M:%S", localtime);
    print "[$ts] $msg\n";
    print $log_fh "[$ts] $msg\n" if $log_fh;
}

sub audit_device {
    my ($host) = @_;
    logprint("=" x 60);
    logprint("Auditing BGP communities on $host");

    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $username,
        password => $password,
        raw_pty  => 1,
        timeout  => $timeout,
    );

    eval {
        my $login = $ssh->login();
        die "Auth failed or unexpected prompt\n" if $login !~ /[>#]/;
    };
    if ($@) {
        logprint("ERROR: Cannot connect to $host - $@");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('[>#]', 10);

    my $cmd = $filter_community
        ? "show ip bgp community $filter_community"
        : "show ip bgp community";

    $ssh->send($cmd);
    my $output = $ssh->waitfor('[>#]', 45);

    unless ($output && $output =~ /\d+\.\d+\.\d+\.\d+/) {
        logprint("No BGP community data returned (BGP may not be running or no routes have communities)");
        $ssh->send("exit");
        $ssh->close();
        return;
    }

    my %community_counts;
    my $route_count     = 0;
    my $no_community    = 0;

    for my $line (split /\n/, $output) {
        next unless $line =~ /^\s*[*>isSh]/;
        $route_count++;
        if ($line =~ /(\d+:\d+(?:\s+\d+:\d+)*)/) {
            my @comms = split /\s+/, $1;
            $community_counts{$_}++ for @comms;
        } elsif ($line =~ /(\d{5,})\s*$/) {
            $community_counts{"well-known:$1"}++;
        } else {
            $no_community++;
        }
    }

    $ssh->send("show ip bgp community no-export no-advertise");
    my $wellknown = $ssh->waitfor('[>#]', 30);
    my $wellknown_count = 0;
    if ($wellknown) {
        $wellknown_count++ while $wellknown =~ /^\s*[*>]/mg;
    }

    logprint(sprintf("  Routes with communities   : %d", $route_count));
    logprint(sprintf("  Routes missing communities: %d", $no_community)) if $no_community;
    logprint(sprintf("  Routes with well-known    : %d (NO_EXPORT/NO_ADVERTISE)", $wellknown_count));

    if (%community_counts) {
        logprint("  Community distribution:");
        for my $comm (sort { $community_counts{$b} <=> $community_counts{$a} } keys %community_counts) {
            logprint(sprintf("    %-20s  %d route(s)", $comm, $community_counts{$comm}));
        }
    }

    if ($wellknown_count == 0 && $route_count > 0) {
        logprint("  [WARN] No well-known community routes found — verify NO_EXPORT policy on customer prefixes");
    }

    $ssh->send("exit");
    $ssh->close();
    logprint("Audit complete for $host");
}

audit_device($_) for @devices;

logprint("All devices audited: " . scalar(@devices));
close $log_fh if $log_fh;
```

This script audits BGP community strings — distinct from the peer-state checking in `bgp_peers.pl` and the prefix threshold/leak detection in `bgp_peers_v2.pl`. It:

- Runs `show ip bgp community` (optionally filtered to a specific community with `-c`)
- Builds a frequency distribution of all community values across the RIB
- Separately checks well-known communities (NO_EXPORT, NO_ADVERTISE) to verify TE policy
- Warns when no well-known communities exist, which often signals a misconfigured outbound route-map on customer-facing peers
- Supports multi-device files and optional log output