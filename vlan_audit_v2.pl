#!/usr/bin/perl
# =============================================================================
# vlan_trunk_prune_check.pl — VLAN Trunk Pruning & Consistency Analyzer
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches and analyzes each trunk interface
#   for VLAN discrepancies — specifically VLANs that are allowed on a trunk
#   but pruned, STP-blocked, or otherwise not forwarding. Useful for catching
#   misconfigured trunk filters, VTP pruning surprises, and STP topology gaps.
#
# What it does:
#   - Runs `show interfaces trunk` and parses all four VLAN lists per trunk:
#       1. VLANs allowed (configured)
#       2. VLANs allowed and active in mgmt domain
#       3. VLANs in spanning tree forwarding state (actually forwarding)
#       4. Derives: pruned (allowed - active) and STP-blocked (active - fwding)
#   - Reports per-trunk discrepancies to STDOUT and an optional log file
#
# Usage:
#   Single device:  perl vlan_trunk_prune_check.pl 192.168.1.1
#   Device list:    perl vlan_trunk_prune_check.pl --file devices.txt
#   With logging:   perl vlan_trunk_prune_check.pl --log trunk_audit.log 10.0.0.1
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH key auth recommended; password prompt handled via --password flag
#
# Options:
#   --user <name>     SSH username (default: admin)
#   --password <pw>   SSH password (prompted if omitted and key auth fails)
#   --file <path>     File containing one device IP/hostname per line
#   --log <path>      Write output to this log file in addition to STDOUT
#   --timeout <sec>   Per-command timeout in seconds (default: 30)
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($user, $password, $device_file, $log_file, $timeout) = ('admin', '', '', '', 30);
my @devices;

GetOptions(
    'user=s'     => \$user,
    'password=s' => \$password,
    'file=s'     => \$device_file,
    'log=s'      => \$log_file,
    'timeout=i'  => \$timeout,
) or die "Usage: $0 [--user <u>] [--password <pw>] [--file <f>] [--log <f>] [--timeout <n>] [device ...]\n";

push @devices, @ARGV;

if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open device file '$device_file': $!\n";
    while (<$fh>) { chomp; push @devices, $_ if /\S/ && !/^#/ }
    close $fh;
}

die "No devices specified. Provide IPs as arguments or use --file.\n" unless @devices;

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log file '$log_file': $!\n";
}

sub log_print {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub expand_vlan_range {
    my $range_str = shift;
    $range_str =~ s/\s+//g;
    my %vlans;
    for my $token (split /,/, $range_str) {
        if ($token =~ /^(\d+)-(\d+)$/) {
            $vlans{$_}++ for $1 .. $2;
        } elsif ($token =~ /^\d+$/) {
            $vlans{$token}++;
        }
    }
    return %vlans;
}

sub audit_device {
    my $host = shift;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    log_print("\n[$ts] Connecting to $host...\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $user,
        password => $password || undef,
        raw_pty  => 1,
        timeout  => $timeout,
    );

    eval { $ssh->run_ssh() or die "SSH failed\n" };
    if ($@) {
        log_print("[ERROR] Cannot connect to $host: $@\n");
        return;
    }

    eval { $ssh->waitfor('>\s*$|\#\s*$', 10) or die "No prompt\n" };
    if ($@) {
        log_print("[ERROR] No prompt on $host: $@\n");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('>\s*$|\#\s*$', 5);

    $ssh->send("show interfaces trunk");
    my $output = $ssh->waitfor('>\s*$|\#\s*$', $timeout);

    $ssh->send("exit");
    $ssh->close();

    unless ($output && $output =~ /Port\s+Mode/i) {
        log_print("[WARN] No trunk data returned from $host (no trunks configured?)\n");
        return;
    }

    my (%allowed, %active, %forwarding);
    my $current_section = '';

    for my $line (split /\n/, $output) {
        if    ($line =~ /VLANs allowed on trunk/i)                    { $current_section = 'allowed' }
        elsif ($line =~ /VLANs allowed and active in management/i)    { $current_section = 'active' }
        elsif ($line =~ /VLANs in spanning tree forwarding/i)         { $current_section = 'forwarding' }
        elsif ($line =~ /^\s*([\w\/\.]+)\s+([\d,\-none]+)\s*$/ && $current_section) {
            my ($iface, $vlans) = ($1, $2);
            next if $vlans eq 'none';
            my %v = expand_vlan_range($vlans);
            if    ($current_section eq 'allowed')    { $allowed{$iface}    = \%v }
            elsif ($current_section eq 'active')     { $active{$iface}     = \%v }
            elsif ($current_section eq 'forwarding') { $forwarding{$iface} = \%v }
        }
    }

    my $found_issue = 0;
    for my $iface (sort keys %allowed) {
        my %allow = %{ $allowed{$iface}    // {} };
        my %act   = %{ $active{$iface}     // {} };
        my %fwd   = %{ $forwarding{$iface} // {} };

        my @pruned  = sort { $a <=> $b } grep { !$act{$_} } keys %allow;
        my @blocked = sort { $a <=> $b } grep { !$fwd{$_} } keys %act;

        if (@pruned || @blocked) {
            $found_issue = 1;
            log_print("  Interface: $iface\n");
            log_print("    PRUNED  (allowed but not active):    " . join(',', @pruned)  . "\n") if @pruned;
            log_print("    BLOCKED (active but not forwarding): " . join(',', @blocked) . "\n") if @blocked;
        }
    }

    log_print("  All trunks clean — no pruned or STP-blocked VLAN discrepancies.\n") unless $found_issue;
}

log_print("=" x 60 . "\n");
log_print("VLAN Trunk Pruning Check — " . strftime("%Y-%m-%d %H:%M:%S", localtime) . "\n");
log_print("Devices: " . scalar(@devices) . "\n");
log_print("=" x 60 . "\n");

audit_device($_) for @devices;

log_print("\nDone.\n");
close $log_fh if $log_fh;