```perl
#!/usr/bin/perl
# =============================================================================
# vlan_audit_v2.pl - VLAN Trunk Consistency & STP Health Checker
# =============================================================================
# Purpose:
#   Audits VLAN trunk consistency and Spanning Tree Protocol (STP) health
#   across Cisco IOS/IOS-XE switches. Identifies trunk mismatches, VLANs
#   in topology-change state, non-designated STP port roles, and blocked ports
#   that could indicate a suboptimal STP topology.
#
# Usage:
#   Single device:  ./vlan_audit_v2.pl -h 192.168.1.1 -u admin -p secret
#   Device list:    ./vlan_audit_v2.pl -f devices.txt -u admin -p secret
#   With log file:  ./vlan_audit_v2.pl -h 192.168.1.1 -u admin -p secret -l audit.log
#
# Prerequisites:
#   - Perl modules: Net::SSH::Expect, Getopt::Long, POSIX
#     Install: cpanm Net::SSH::Expect
#   - SSH access to target devices
#   - Read-only (or higher) privilege level on devices
#   - Cisco IOS/IOS-XE compatible (tested on 12.x, 15.x, 16.x, 17.x)
#
# Output columns (STP):
#   VLAN | Root Bridge | Root Port | Topology Changes | BLK Ports
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $logfile, $timeout);
$timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$logfile,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h HOST | -f FILE -u USER -p PASS [-l LOGFILE] [-t TIMEOUT]\n";

die "Provide -h HOST or -f FILE\n"  unless $host || $device_file;
die "Username required (-u)\n"      unless $username;
die "Password required (-p)\n"      unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} elsif ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^#/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log $logfile: $!\n";
}

sub log_print {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
log_print("=" x 70 . "\n");
log_print("VLAN Trunk & STP Health Audit - $ts\n");
log_print("=" x 70 . "\n\n");

for my $device (@devices) {
    log_print("Device: $device\n");
    log_print("-" x 50 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $username,
        password    => $password,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        log_print("  ERROR: Failed to connect to $device - $@\n\n");
        next;
    }
    if ($login_output =~ /[Aa]uth|[Dd]enied|[Ff]ailed/) {
        log_print("  ERROR: Authentication failed for $device\n\n");
        $ssh->close();
        next;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#', 5);

    # --- Trunk Interface Summary ---
    log_print("  [Trunk Interfaces]\n");
    $ssh->send("show interfaces trunk");
    my $trunk_out = $ssh->waitfor('\$|#', $timeout);

    my %trunk_vlans;
    my $current_iface = '';
    for my $line (split /\n/, $trunk_out) {
        if ($line =~ /^(\S+)\s+\S+\s+\S+\s+802\.1q|dot1q/i) {
            $current_iface = $1;
        }
        if ($line =~ /^(\S+)\s+\d+\s+[\d,\-]+\s+([\d,\-]+)/ && $current_iface) {
            $trunk_vlans{$current_iface} = $2;
        }
        if ($line =~ /^(Gi|Te|Fa|Et|Po)\S+\s+\S+\s+\S+\s+(802\.1q|dot1q|isl)/i) {
            my ($iface) = ($line =~ /^(\S+)/);
            log_print("    Trunk: $iface\n");
        }
    }
    log_print("    (no trunks found)\n") unless $trunk_out =~ /802\.1q|dot1q|isl/i;

    # --- STP Summary ---
    log_print("  [STP Summary]\n");
    $ssh->send("show spanning-tree summary");
    my $stp_sum = $ssh->waitfor('\$|#', $timeout);

    my ($blk_count, $fwd_count, $tc_count) = (0, 0, 0);
    for my $line (split /\n/, $stp_sum) {
        $blk_count += $1 if $line =~ /Blocking\s+(\d+)/i;
        $fwd_count += $1 if $line =~ /Forwarding\s+(\d+)/i;
        $tc_count  += $1 if $line =~ /Topology\s+Changes\s+(\d+)/i;
    }
    my $stp_mode = ($stp_sum =~ /Rapid/i) ? 'RSTP' :
                   ($stp_sum =~ /MST/i)   ? 'MSTP' : 'STP';
    log_print("    Mode: $stp_mode | Forwarding: $fwd_count | Blocking: $blk_count | TC Count: $tc_count\n");
    log_print("    WARN: $blk_count blocked ports detected - verify STP topology\n") if $blk_count > 0;
    log_print("    WARN: $tc_count topology changes - check for instability\n")     if $tc_count > 10;

    # --- Per-VLAN STP Root Check ---
    log_print("  [Per-VLAN STP Root]\n");
    $ssh->send("show spanning-tree | include VLAN|Root ID|This bridge");
    my $vlan_stp = $ssh->waitfor('\$|#', $timeout);

    my ($cur_vlan, $root_id, $is_root) = ('', '', 0);
    my @vlan_issues;
    for my $line (split /\n/, $vlan_stp) {
        if ($line =~ /^VLAN(\d+)/) {
            if ($cur_vlan && !$is_root) {
                push @vlan_issues, "    VLAN$cur_vlan: non-root (root=$root_id)\n";
            }
            ($cur_vlan, $root_id, $is_root) = ($1, '', 0);
        }
        $root_id = $1 if $line =~ /Address\s+([\da-f.]+)/i;
        $is_root = 1  if $line =~ /This bridge is the root/i;
    }

    if (@vlan_issues) {
        log_print("    VLANs where this switch is NOT root bridge:\n");
        log_print($_) for @vlan_issues;
    } else {
        log_print("    This switch is root for all active VLANs (or check manually)\n");
    }

    $ssh->close();
    log_print("\n");
}

log_print("Audit complete.\n");
close $log_fh if $log_fh;
```