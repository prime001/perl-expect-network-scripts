```perl
#!/usr/bin/perl
#
# bgp_prefix_analysis.pl - BGP Prefix Count and Route Leak Detection
#
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE routers via SSH and analyzes
#   BGP prefix advertisements for anomalies: peers exceeding prefix limits,
#   unexpected route counts, and potential route leaks (overly-specific prefixes).
#   Useful for NOC triage, capacity planning, and security audits.
#
# Usage:
#   Single device:  ./bgp_prefix_analysis.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./bgp_prefix_analysis.pl -f devices.txt -u admin -p secret
#   With logging:   ./bgp_prefix_analysis.pl -h 10.0.0.1 -u admin -p secret -l bgp_report.log
#   Threshold:      ./bgp_prefix_analysis.pl -h 10.0.0.1 -u admin -p secret -t 750000
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   Devices must have SSH enabled and the user needs privilege level 1+
#
# Output:
#   Prints per-peer prefix counts, flags peers near/over limits, and
#   summarizes any /25+ prefixes received (potential deaggregation/leaks).
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $device_file, $username, $password, $log_file, $prefix_threshold);
my $timeout    = 30;
$prefix_threshold = 800000;

GetOptions(
    'h|host=s'      => \$host_arg,
    'f|file=s'      => \$device_file,
    'u|user=s'      => \$username,
    'p|pass=s'      => \$password,
    'l|log=s'       => \$log_file,
    't|threshold=i' => \$prefix_threshold,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l logfile] [-t threshold]\n";

die "Must specify -h or -f\n"  unless $host_arg || $device_file;
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

sub analyze_device {
    my ($host) = @_;
    logprint("=" x 60);
    logprint("Connecting to $host");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $username,
        password     => $password,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    eval {
        my $login = $ssh->login();
        if ($login !~ /[>#]/) {
            die "Authentication failed or unexpected prompt on $host\n";
        }
    };
    if ($@) {
        logprint("ERROR: Cannot connect to $host - $@");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('[>#]', 10);

    $ssh->send("show ip bgp summary");
    my $summary = $ssh->waitfor('[>#]', 30);

    unless ($summary) {
        logprint("ERROR: No response to BGP summary on $host");
        $ssh->close();
        return;
    }

    my @peers;
    my $router_id = '';
    for my $line (split /\n/, $summary) {
        $router_id = $1 if $line =~ /BGP router identifier\s+(\S+)/;
        if ($line =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\d+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)\s+(\S+)/) {
            push @peers, { ip => $1, as => $2, pfx => $3, updown => $4 };
        }
    }

    logprint("Router ID: $router_id  |  Peers found: " . scalar(@peers));

    my $warn_count = 0;
    for my $p (@peers) {
        my $pct  = int(($p->{pfx} / $prefix_threshold) * 100);
        my $flag = '';
        if ($p->{updown} =~ /^\d/) {
            $flag = " [DOWN]";
            $warn_count++;
        } elsif ($p->{pfx} >= $prefix_threshold) {
            $flag = " [*** OVER THRESHOLD ***]";
            $warn_count++;
        } elsif ($p->{pfx} >= $prefix_threshold * 0.9) {
            $flag = " [WARN: ${pct}% of threshold]";
            $warn_count++;
        }
        logprint(sprintf("  Peer %-15s AS %-8s Prefixes: %-8d Up/Down: %s%s",
            $p->{ip}, $p->{as}, $p->{pfx}, $p->{updown}, $flag));
    }

    $ssh->send("show ip bgp | include /2[5-9]|/3[012]");
    my $specifics = $ssh->waitfor('[>#]', 45);

    my %leak_counts;
    if ($specifics) {
        for my $line (split /\n/, $specifics) {
            if ($line =~ /(\d+\.\d+\.\d+\.\d+)\s*\/([2-3]\d)/) {
                my $len = $2;
                $leak_counts{$len}++ if $len >= 25;
            }
        }
    }

    if (%leak_counts) {
        logprint("  Potentially deaggregated prefixes (>=25 bit masks):");
        for my $len (sort { $a <=> $b } keys %leak_counts) {
            logprint(sprintf("    /%d  ->  %d prefix(es)", $len, $leak_counts{$len}));
        }
        $warn_count++ if %leak_counts;
    } else {
        logprint("  No deaggregated prefixes detected (>=25-bit masks).");
    }

    logprint("Summary for $host: $warn_count warning(s)");
    $ssh->send("exit");
    $ssh->close();
}

for my $dev (@devices) {
    analyze_device($dev);
}

logprint("Analysis complete. Devices checked: " . scalar(@devices));
close $log_fh if $log_fh;
```