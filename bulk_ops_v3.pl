#!/usr/bin/perl
# =============================================================================
# stp_audit.pl - Spanning Tree Protocol Audit Tool
# =============================================================================
# Purpose:
#   Connects to Cisco IOS/IOS-XE network devices and audits Spanning Tree
#   Protocol (STP) status. Identifies root bridge placement, port states,
#   topology change counters (instability indicator), and BPDU Guard violations.
#   Useful for validating STP design intent and troubleshooting loops.
#
# Usage:
#   Single device:  perl stp_audit.pl -h 192.168.1.1 -u admin -p password
#   Device file:    perl stp_audit.pl -f devices.txt -u admin -p password
#   With log:       perl stp_audit.pl -h 192.168.1.1 -u admin -p password -l stp.log
#   Specific VLANs: perl stp_audit.pl -h 192.168.1.1 -u admin -p password -v 1,10,20
#
# Device file format: one IP or hostname per line; lines starting with # ignored.
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH enabled on devices; account needs privilege for 'show spanning-tree'
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $username, $password, $logfile, $vlans_opt, $timeout);
$timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'l|log=s'     => \$logfile,
    'v|vlans=s'   => \$vlans_opt,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOG] [-v VLANS] [-t TIMEOUT]\n";

die "Must specify -h HOST or -f FILE\n" unless $host || $file;
die "Must specify -u USERNAME\n"        unless $username;
die "Must specify -p PASSWORD\n"        unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $file) or die "Cannot open '$file': $!\n";
    while (<$fh>) {
        chomp; next if /^\s*$/ || /^#/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log '$logfile': $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=" x 68);
out("STP Audit Report  -  $ts");
out("=" x 68);

audit_device($_) for @devices;

out("\nAudit complete. Devices checked: " . scalar(@devices));
close $log_fh if $log_fh;

# ---------------------------------------------------------------------------

sub audit_device {
    my ($device) = @_;
    out("\n--- $device ---");

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $username,
        password => $password,
        raw_pty  => 1,
        timeout  => $timeout,
    );

    my $login;
    eval { $login = $ssh->login() };
    if ($@ || $login !~ /[>#]/) {
        out("  ERROR: Login failed - " . ($@ // 'unexpected prompt'));
        return;
    }

    # Suppress paging
    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\s*[>#]', $timeout);

    # Detect STP mode and global stats
    $ssh->send("show spanning-tree summary\n");
    my $summary = $ssh->waitfor('\s*[>#]', $timeout) // '';

    my $mode = 'unknown';
    $mode = $1 if $summary =~ /Switch is in (\S+) mode/i;
    $mode = $1 if $summary =~ /Spanning tree enabled protocol (\S+)/i;
    out("  STP Mode       : $mode");

    my $fwd = () = $summary =~ /\bforwarding\b/gi;
    my $blk = () = $summary =~ /\bblocking\b/gi;
    out("  Ports Fwd/Blk  : $fwd / $blk");

    if ($summary =~ /topology\s+changes\s+(\d+)/i) {
        my $tc = $1;
        my $flag = $tc > 100 ? '  <<< HIGH - possible instability' : '';
        out("  Topology Changes: $tc$flag");
    }

    # Root bridge check per VLAN
    my @vlans;
    if ($vlans_opt) {
        @vlans = split /,/, $vlans_opt;
    } else {
        my %seen;
        push @vlans, $1 while $summary =~ /VLAN0*(\d+)/g and !$seen{$1}++;
        @vlans = @vlans[0 .. ($#vlans < 9 ? $#vlans : 9)];
    }

    if (@vlans) {
        out("  Root Bridge per VLAN:");
        for my $vlan (@vlans) {
            $ssh->send("show spanning-tree vlan $vlan | include root|Root|This\n");
            my $r = $ssh->waitfor('\s*[>#]', $timeout) // '';

            if ($r =~ /This bridge is the root/i) {
                out("    VLAN $vlan  : ** THIS DEVICE IS ROOT **");
            } elsif ($r =~ /Address\s+([0-9a-fA-F.]+)/i) {
                my $mac  = $1;
                my $cost = $r =~ /Cost\s+(\d+)/i ? $1 : 'n/a';
                out("    VLAN $vlan  : Root $mac  path-cost $cost");
            } else {
                out("    VLAN $vlan  : not active or VLAN absent");
            }
        }
    }

    # BPDU Guard violations (err-disabled ports)
    $ssh->send("show spanning-tree detail | include err-disabled\n");
    my $bpdu = $ssh->waitfor('\s*[>#]', $timeout) // '';
    my $errd = () = $bpdu =~ /err-disabled/gi;
    out("  BPDU Guard err-disabled: $errd" . ($errd ? '  <<< ACTION REQUIRED' : ''));

    $ssh->close();
}

sub out {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}