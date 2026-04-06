#!/usr/bin/perl
# =============================================================================
# 014_interface_compliance.pl - Interface Configuration Compliance Audit
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and checks interface
#   configurations against common hardening and operational standards:
#     - Access ports missing 'spanning-tree portfast'
#     - Trunk ports using native VLAN 1 (security baseline violation)
#     - Switchports lacking a description (documentation gap)
#     - Unused ports that are administratively up (attack surface)
#   Complements 004_interface_audit.pl which checks runtime error counters;
#   this script checks the configuration itself, not operational state.
#
# Usage:
#   ./014_interface_compliance.pl -h <host>        Single device
#   ./014_interface_compliance.pl -f <hosts_file>  One IP/hostname per line
#
#   Optional flags:
#     -u <username>   Default: $NET_USER env var or 'admin'
#     -p <password>   Default: $NET_PASS env var (prefer env over -p)
#     -l <logfile>    Append full output to logfile in addition to STDOUT
#     --strict        Exit non-zero if any violations found (for CI pipelines)
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#   'show running-config' read access on target devices.
#   Key-based SSH strongly recommended; use NET_USER/NET_PASS env vars to
#   avoid credentials in shell history or process list.
#
# Violation tags:
#   [NO-PORTFAST]  Access port without spanning-tree portfast
#   [NATIVE-VLAN1] Trunk port with native VLAN 1 (or no explicit native VLAN)
#   [NO-DESC]      Switchport with no description configured
#   [IDLE-UP]      Non-routed port that is up but carries no VLAN/IP assignment
#
# Example:
#   NET_USER=netops NET_PASS=s3cr3t \
#     ./014_interface_compliance.pl -f distribution.txt -l compliance.log --strict
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $hosts_file, $username, $password, $logfile, $strict);
$username = $ENV{NET_USER} // 'admin';
$password = $ENV{NET_PASS} // '';

GetOptions(
    'h|host=s'  => \$host,
    'f|file=s'  => \$hosts_file,
    'u|user=s'  => \$username,
    'p|pass=s'  => \$password,
    'l|log=s'   => \$logfile,
    'strict'    => \$strict,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile] [--strict]\n";

die "Specify -h <host> or -f <file>\n" unless $host || $hosts_file;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $hosts_file or die "Cannot open $hosts_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*#/ || /^\s*$/; push @devices, $_; }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open logfile '$logfile': $!\n";
}

my $ts         = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $total_viol = 0;

sub emit {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my ($device) = @_;
    emit("\n" . "=" x 66 . "\n");
    emit("COMPLIANCE AUDIT  host=$device  ts=$ts\n");
    emit("=" x 66 . "\n");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host       => $device,
            user       => $username,
            password   => $password,
            raw_pty    => 1,
            timeout    => 30,
            ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=no',
        );
        $ssh->login();
    };
    if ($@) {
        emit("  ERROR: cannot connect to $device: $@\n");
        return;
    }

    $ssh->exec("terminal length 0");
    my $run = $ssh->exec("show running-config");
    $ssh->close();

    # Parse interface stanzas from running-config
    my (%iface, $cur);
    for my $line (split /\n/, $run) {
        if ($line =~ /^interface\s+(\S+)/i) {
            $cur = $1;
            next;
        }
        next unless $cur;
        if ($line =~ /^!/ || ($line !~ /^\s/ && $line !~ /^$/)) {
            $cur = undef; next;
        }
        $iface{$cur}{desc}       = $1   if $line =~ /^\s+description\s+(.+)/i;
        $iface{$cur}{mode}       = $1   if $line =~ /^\s+switchport mode\s+(\S+)/i;
        $iface{$cur}{access_vl}  = $1   if $line =~ /^\s+switchport access vlan\s+(\d+)/i;
        $iface{$cur}{native_vl}  = $1   if $line =~ /^\s+switchport trunk native vlan\s+(\d+)/i;
        $iface{$cur}{portfast}   = 1    if $line =~ /^\s+spanning-tree portfast\b/i;
        $iface{$cur}{shutdown}   = 1    if $line =~ /^\s+shutdown/i;
        $iface{$cur}{ip}         = 1    if $line =~ /^\s+ip address\s+\S/i;
        $iface{$cur}{switchport} = 1    if $line =~ /^\s+switchport/i;
        $iface{$cur}{routed}     = 1    if $line =~ /^\s+no switchport/i;
    }

    my ($n_pf, $n_nv, $n_nd, $n_iu) = (0, 0, 0, 0);

    for my $intf (sort keys %iface) {
        my $e = $iface{$intf};
        next if $intf =~ /^(Loopback|Tunnel|Vlan|Null)/i;   # L3/virtual — skip
        next if $e->{shutdown};

        my $mode       = $e->{mode}      // '';
        my $native_vl  = $e->{native_vl} // 1;   # IOS default is VLAN 1
        my $is_sw      = $e->{switchport} && !$e->{routed};

        # [NO-PORTFAST] access ports without portfast
        if ($is_sw && $mode eq 'access' && !$e->{portfast}) {
            emit(sprintf "  [NO-PORTFAST] %-38s access vlan %s\n",
                $intf, $e->{access_vl} // '?');
            $n_pf++;
        }

        # [NATIVE-VLAN1] trunk ports on native VLAN 1
        if ($is_sw && $mode eq 'trunk' && $native_vl == 1) {
            emit(sprintf "  [NATIVE-VLAN1] %-37s native vlan=1 (default)\n", $intf);
            $n_nv++;
        }

        # [NO-DESC] switchports missing description
        if ($is_sw && !$e->{desc}) {
            emit(sprintf "  [NO-DESC]     %-38s mode=%-6s\n", $intf, $mode || '?');
            $n_nd++;
        }

        # [IDLE-UP] switchport up, no VLAN assignment, not a trunk
        if ($is_sw && $mode ne 'trunk' && !$e->{access_vl} && !$e->{shutdown}) {
            emit(sprintf "  [IDLE-UP]     %-38s no vlan assigned, port is up\n", $intf);
            $n_iu++;
        }
    }

    my $viol = $n_pf + $n_nv + $n_nd + $n_iu;
    $total_viol += $viol;
    emit(sprintf "\n  Violations: %d  (portfast=%d  native-vlan1=%d  no-desc=%d  idle-up=%d)\n",
        $viol, $n_pf, $n_nv, $n_nd, $n_iu);
}

audit_device($_) for @devices;
emit("\nTotal violations across all devices: $total_viol\n");

close $log_fh if $log_fh;

exit(($strict && $total_viol) ? 1 : 0);