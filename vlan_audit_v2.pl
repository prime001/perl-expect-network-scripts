#!/usr/bin/perl
# =============================================================================
# stp_audit.pl - Spanning Tree Protocol Topology Auditor
# =============================================================================
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches via SSH and audits the Spanning Tree
#   Protocol topology. Reports root bridge placement, port roles/states, active
#   topology changes, and change counters per VLAN. Flags anomalies that
#   indicate instability or misconfiguration.
#
# Usage:
#   Single device:  ./stp_audit.pl -h 192.168.1.1 [-u admin] [-p password]
#   Device list:    ./stp_audit.pl -f switches.txt [-u admin] [-p password]
#   With logging:   ./stp_audit.pl -h 192.168.1.1 -l /var/log/stp_audit.log
#
# Prerequisites:
#   cpanm Net::SSH::Expect Getopt::Long
#
# Environment variables (override CLI args):
#   NET_USER, NET_PASS, NET_ENABLE
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $enable, $logfile, $help);
my $timeout = 20;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$file,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'e|enable=s'  => \$enable,
    'l|log=s'     => \$logfile,
    't|timeout=i' => \$timeout,
    'help'        => \$help,
) or usage();

usage() if $help || (!$host && !$file);

$user   ||= $ENV{NET_USER}   || 'admin';
$pass   ||= $ENV{NET_PASS}   || die "Password required: use -p or set NET_PASS\n";
$enable ||= $ENV{NET_ENABLE} || $pass;

my @devices;
if ($file) {
    open(my $fh, '<', $file) or die "Cannot open device file '$file': $!\n";
    while (<$fh>) { chomp; push @devices, $_ if /\S/ && !/^\s*#/ }
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log '$logfile': $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=" x 60);
out("STP Audit Report - $ts");
out("Devices: " . scalar(@devices));
out("=" x 60);

for my $device (@devices) {
    audit_device($device);
}

close $log_fh if $log_fh;

sub audit_device {
    my ($device) = @_;
    out("\n[Device: $device]");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $device,
            user     => $user,
            password => $pass,
            raw_pty  => 1,
            timeout  => $timeout,
        );
    };
    if ($@) {
        out("  ERROR: Cannot create SSH session: $@");
        return;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        out("  ERROR: Authentication failed (check credentials)");
        return;
    }

    $ssh->exec("terminal length 0");

    my $priv = $ssh->exec("show privilege") // '';
    if ($priv =~ /Current privilege level is (\d+)/ && $1 < 15) {
        $ssh->send("enable");
        $ssh->waitfor('Password:', 5);
        $ssh->send($enable);
        $ssh->waitfor('#', 10) or do {
            out("  ERROR: Enable mode failed");
            $ssh->close();
            return;
        };
    }

    parse_stp_summary($ssh->exec("show spanning-tree summary"));
    parse_stp_detail($ssh->exec("show spanning-tree detail"));

    $ssh->close();
}

sub parse_stp_summary {
    my ($raw) = @_;
    return unless defined $raw;

    for (split /\n/, $raw) {
        out("  Root bridge for: $1") if /Root bridge for:\s+(.+)/;
        out("  STP-active VLANs: $1") if /(\d+) vlans? in spanning tree/i;
        out("  WARN: Active topology change flag set") if /Topology change flag\s+set/i;
        out("  STP mode: $1") if /^(Rapid PVST|PVST|MST|RSTP)\+?\s+is/i;
        out("  Portfast BPDU guard: $1") if /Portfast BPDU Guard\s+is\s+(\w+)/i;
    }
}

sub parse_stp_detail {
    my ($raw) = @_;
    return unless defined $raw;

    my ($current_vlan, @root_vlans, @high_tc_vlans);

    for (split /\n/, $raw) {
        $current_vlan = $1 if /VLAN(\d+)\s+is (?:executing|in)/i;
        next unless defined $current_vlan;

        if (/Bridge is the root/i) {
            push @root_vlans, $current_vlan unless grep { $_ eq $current_vlan } @root_vlans;
        }
        if (/Number of topology changes (\d+)/i && $1 > 10) {
            out("  WARN: VLAN $current_vlan - $1 topology changes (instability risk)");
        }
        if (/Last topology change from (\S+)/i) {
            out("  INFO: VLAN $current_vlan - last TC from $1");
        }
        if (/(\S+)\s+of \S+\s+is (?:BLK|blocking)/i) {
            out("  INFO: VLAN $current_vlan - $1 is blocking");
        }
        if (/port is (?:inconsistent|broken|err-disabled)/i) {
            out("  WARN: VLAN $current_vlan - STP inconsistent/err-disabled port detected");
        }
    }

    if (@root_vlans) {
        out("  Root bridge for VLANs: " . join(', ', sort { $a <=> $b } @root_vlans));
    } else {
        out("  INFO: Not root bridge for any VLAN on this device");
    }
}

sub out {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}

sub usage {
    print <<'END';
Usage: stp_audit.pl -h <host> | -f <file> [options]

  -h, --host     Device IP or hostname
  -f, --file     File containing one device per line (# = comment)
  -u, --user     SSH username (default: admin or $NET_USER)
  -p, --pass     SSH password (or $NET_PASS env var)
  -e, --enable   Enable secret (default: same as -p or $NET_ENABLE)
  -l, --log      Append results to log file
  -t, --timeout  SSH timeout seconds (default: 20)
  --help         Show this help

Examples:
  ./stp_audit.pl -h 10.0.0.1 -u admin -p secret
  ./stp_audit.pl -f core_switches.txt -p secret -l stp_$(date +%Y%m%d).log
  NET_PASS=secret ./stp_audit.pl -f switches.txt -l /var/log/stp_weekly.log
END
    exit 1;
}