#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# Script: 010_bgp_peers.pl
# Purpose: Audit BGP peer states across one or more routers via SSH.
#          Connects to each device, runs 'show bgp summary' (IOS/IOS-XE) or
#          equivalent, parses peer states, and flags any non-Established peers.
#
# Usage:
#   Single device:  perl 010_bgp_peers.pl --host 10.0.0.1
#   Device file:    perl 010_bgp_peers.pl --file routers.txt
#   With logging:   perl 010_bgp_peers.pl --file routers.txt --log bgp_audit.log
#   Custom creds:   perl 010_bgp_peers.pl --host 10.0.0.1 --user admin --pass secret
#
# Prerequisites:
#   cpanm Net::SSH::Expect
#   SSH key-based auth or password auth to target devices
#   Devices must support 'show bgp summary' (Cisco IOS/IOS-XE/NX-OS)
#
# Device file format: one IP or hostname per line; lines starting with # ignored
# =============================================================================

my $username  = $ENV{NET_USER} // 'admin';
my $password  = $ENV{NET_PASS} // '';
my $host_arg  = '';
my $file_arg  = '';
my $log_file  = '';
my $timeout   = 15;
my $vrf       = '';

GetOptions(
    'host=s'    => \$host_arg,
    'file=s'    => \$file_arg,
    'user=s'    => \$username,
    'pass=s'    => \$password,
    'log=s'     => \$log_file,
    'timeout=i' => \$timeout,
    'vrf=s'     => \$vrf,
) or die "Usage: $0 [--host HOST | --file FILE] [--user USER] [--pass PASS] [--log FILE] [--vrf VRF]\n";

die "Specify --host or --file\n" unless $host_arg || $file_arg;

my @hosts;
if ($host_arg) {
    push @hosts, $host_arg;
} else {
    open my $fh, '<', $file_arg or die "Cannot open $file_arg: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @hosts, $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub log_print {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
log_print("=" x 70 . "\n");
log_print("BGP Peer Audit  --  $timestamp\n");
log_print("=" x 70 . "\n\n");

my $bgp_cmd = $vrf ? "show bgp vpnv4 unicast vrf $vrf summary" : "show bgp summary";

my ($total_peers, $down_peers) = (0, 0);

for my $host (@hosts) {
    log_print("Host: $host\n");
    log_print("-" x 50 . "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $host,
            user        => $username,
            password    => $password,
            raw_pty     => 1,
            timeout     => $timeout,
        );
    };
    if ($@ || !$ssh) {
        log_print("  ERROR: Could not create SSH session: $@\n\n");
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        log_print("  ERROR: Authentication failed or connection refused: $@\n\n");
        next;
    }

    # Disable paging
    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|\#|>', $timeout) or log_print("  WARN: Prompt not seen after terminal length 0\n");

    $ssh->send("$bgp_cmd\n");
    my $output = $ssh->waitfor('\$|\#|>', $timeout);

    unless (defined $output && length $output) {
        log_print("  ERROR: No output received from device\n\n");
        $ssh->close();
        next;
    }

    my $found_peers = 0;
    for my $line (split /\n/, $output) {
        # IOS BGP summary peer lines: start with IP address
        next unless $line =~ /^(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)/;
        my ($peer_ip, $state_or_prefixes) = ($1, $2);
        $total_peers++;
        $found_peers++;

        # If the last field is not a number it's a state string (not Established)
        if ($state_or_prefixes =~ /^\d+$/) {
            log_print(sprintf("  %-18s  Established  (prefixes: %s)\n", $peer_ip, $state_or_prefixes));
        } else {
            log_print(sprintf("  %-18s  *** %s ***\n", $peer_ip, uc($state_or_prefixes)));
            $down_peers++;
        }
    }

    log_print("  (no BGP peers found or output format unrecognized)\n") unless $found_peers;
    log_print("\n");

    $ssh->send("exit\n");
    $ssh->close();
}

log_print("=" x 70 . "\n");
log_print(sprintf("Summary: %d peers checked, %d non-Established\n", $total_peers, $down_peers));
log_print("=" x 70 . "\n");

close $log_fh if $log_fh;

exit($down_peers > 0 ? 1 : 0);