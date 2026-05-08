#!/usr/bin/perl
# =============================================================================
# cdp_lldp_neighbors.pl - CDP/LLDP Neighbor Discovery and Topology Mapper
#
# Purpose:
#   Connects to network devices via SSH and collects CDP and/or LLDP neighbor
#   information. Useful for topology documentation, verifying cabling changes,
#   and auditing what is physically adjacent to each device.
#
# Usage:
#   ./cdp_lldp_neighbors.pl -h <host> [-u <user>] [-p <pass>] [-l <logfile>]
#   ./cdp_lldp_neighbors.pl -f <hosts.txt> [-u <user>] [-p <pass>] [-l <logfile>]
#
# Env vars: NET_USER, NET_PASS (used if -u/-p not provided)
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   cpan Getopt::Long
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $hosts_file, $username, $password, $logfile);
my $timeout = 20;

GetOptions(
    'h|host=s'    => \$host_arg,
    'f|file=s'    => \$hosts_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'l|log=s'     => \$logfile,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile]\n";

$username //= $ENV{NET_USER} // die "Username required (-u or NET_USER env)\n";
$password //= $ENV{NET_PASS} // die "Password required (-p or NET_PASS env)\n";

my @hosts;
if ($host_arg) {
    push @hosts, $host_arg;
} elsif ($hosts_file) {
    open my $fh, '<', $hosts_file or die "Cannot open $hosts_file: $!\n";
    while (<$fh>) { chomp; push @hosts, $_ unless /^\s*[#\s]/; }
    close $fh;
} else {
    die "Specify -h <host> or -f <hosts_file>\n";
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or warn "Cannot open log $logfile: $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
out("CDP/LLDP Neighbor Discovery  —  $ts\n");
out("=" x 72 . "\n");

for my $host (@hosts) {
    out("\nDevice: $host\n");
    out("-" x 50 . "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $host,
            user     => $username,
            password => $password,
            raw_pty  => 1,
            timeout  => $timeout,
        );
    };
    if ($@ || !$ssh) {
        out("  ERROR: Cannot create SSH session: $@\n");
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@) {
        out("  ERROR: Authentication failed — $@\n");
        next;
    }

    $ssh->exec("terminal length 0");

    my @neighbors;

    # --- CDP ---
    my $cdp = $ssh->exec("show cdp neighbors detail");
    if ($cdp && $cdp !~ /not enabled|Invalid input|% Error/i) {
        my ($dev, $loc, $rem, $plat, $ip);
        for my $line (split /\n/, $cdp) {
            if ($line =~ /^Device ID:\s*(\S+)/) {
                push @neighbors, { proto => 'CDP', dev => $dev,
                    loc => $loc//'?', rem => $rem//'?',
                    plat => $plat//'?', ip => $ip//'?' } if $dev;
                ($dev, $loc, $rem, $plat, $ip) = ($1, undef, undef, undef, undef);
            }
            $loc  = $1 if !$loc  && $line =~ /Interface:\s*(\S+),/;
            $rem  = $1 if !$rem  && $line =~ /Port ID \(outgoing port\):\s*(\S+)/;
            $plat = $1 if !$plat && $line =~ /Platform:\s*(.*?),/;
            $ip   = $1 if !$ip   && $line =~ /IP(?:v4)? [Aa]ddress:\s*(\d[\d.]+)/;
        }
        push @neighbors, { proto => 'CDP', dev => $dev,
            loc => $loc//'?', rem => $rem//'?',
            plat => $plat//'?', ip => $ip//'?' } if $dev;
    }

    # --- LLDP (fallback or supplement) ---
    my $lldp = $ssh->exec("show lldp neighbors detail");
    if ($lldp && $lldp !~ /not enabled|Invalid input|% Error/i) {
        my ($dev, $loc, $rem, $ip);
        for my $line (split /\n/, $lldp) {
            $loc = $1 if $line =~ /^Local\s+Intf(?:erface)?:\s*(\S+)/i;
            $dev = $1 if $line =~ /System Name:\s*(\S+)/i;
            $rem = $1 if $line =~ /Port (?:id|ID):\s*(\S+)/i;
            $ip  = $1 if $line =~ /(\d+\.\d+\.\d+\.\d+)/ && !$ip;
            if ($dev && $loc && $rem) {
                push @neighbors, { proto => 'LLDP', dev => $dev,
                    loc => $loc, rem => $rem, plat => '-', ip => $ip//'?' };
                ($dev, $loc, $rem, $ip) = (undef, undef, undef, undef);
            }
        }
    }

    $ssh->close();

    if (@neighbors) {
        out(sprintf("  %-6s  %-22s  %-18s  %-18s  %-15s\n",
            "Proto", "Neighbor", "Local Port", "Remote Port", "Mgmt IP"));
        out("  " . "-" x 84 . "\n");
        for my $n (@neighbors) {
            out(sprintf("  %-6s  %-22s  %-18s  %-18s  %-15s\n",
                $n->{proto},
                substr($n->{dev},  0, 22),
                substr($n->{loc},  0, 18),
                substr($n->{rem},  0, 18),
                $n->{ip}));
        }
        out("  Total: " . scalar(@neighbors) . " neighbor(s)\n");
    } else {
        out("  No CDP/LLDP neighbors found or protocol not enabled.\n");
    }
}

out("\n" . "=" x 72 . "\n");
out("Done.\n");
close $log_fh if $log_fh;