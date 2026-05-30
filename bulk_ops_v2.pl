#!/usr/bin/perl
# =============================================================================
# stp_audit.pl - Spanning Tree Protocol Audit Tool
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches via SSH and audits spanning tree
#   state: root bridge identity, port roles/states, topology change counters,
#   and blocked/inconsistent ports. Useful for pre-change topology verification
#   and troubleshooting STP instability.
#
# Usage:
#   ./stp_audit.pl -h <host> [-u <user>] [-p <pass>] [-v <vlan_id>] [-l <log>]
#   ./stp_audit.pl -f <device_file> [-u <user>] [-p <pass>] [-l <log>]
#
# Device file format (one entry per line, # = comment):
#   192.168.1.1
#   192.168.1.2  altuser  altpass
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#   SSH access with 'show spanning-tree' privilege on target devices
#
# Environment variables (fallback if -u/-p not given):
#   NET_USER, NET_PASS
#
# Examples:
#   ./stp_audit.pl -h 10.0.0.1 -u admin -p secret
#   ./stp_audit.pl -h 10.0.0.1 -u admin -p secret -v 100
#   ./stp_audit.pl -f switches.txt -l /var/log/stp_audit.log
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($host, $user, $pass, $vlan, $logfile, $device_file, $timeout);
$timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'v|vlan=s'    => \$vlan,
    'l|log=s'     => \$logfile,
    'f|file=s'    => \$device_file,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-v vlan] [-l log]\n";

$user //= $ENV{NET_USER} // 'admin';
$pass //= $ENV{NET_PASS} // die "Password required: use -p or set NET_PASS\n";

my @devices;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        next unless length;
        my @f = split /\s+/;
        push @devices, { host => $f[0], user => $f[1] // $user, pass => $f[2] // $pass };
    }
    close $fh;
} elsif ($host) {
    push @devices, { host => $host, user => $user, pass => $pass };
} else {
    die "Must specify -h <host> or -f <device_file>\n";
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!\n";
}

sub out {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_stp {
    my ($dev) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);

    out("\n" . "=" x 62 . "\n");
    out("Host : $dev->{host}    Time : $ts\n");
    out("=" x 62 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $dev->{host},
        user     => $dev->{user},
        password => $dev->{pass},
        raw_pty  => 1,
        timeout  => $timeout,
    );

    eval {
        my $banner = $ssh->login();
        die "Login failed (got: $banner)\n" unless $banner =~ /[>#]/;

        $ssh->send("terminal length 0");
        $ssh->waitfor('\s*[>#]', $timeout) or die "Timeout after 'terminal length 0'\n";

        my $cmd = $vlan ? "show spanning-tree vlan $vlan" : "show spanning-tree summary totals";
        $ssh->send($cmd);
        my $out = $ssh->waitfor('\s*[>#]', $timeout) or die "Timeout on '$cmd'\n";

        out("Command: $cmd\n\n");

        my $is_root = 0;
        my @blocked_ports;

        for my $line (split /\n/, $out) {
            if ($line =~ /This bridge is the root/i) {
                $is_root = 1;
                out("  [ROOT]  This switch is the root bridge\n");
            }
            if ($line =~ /Root\s+ID.*Priority\s+(\d+)/i || $line =~ /Root priority\s+(\d+)/i) {
                out("  Root Priority   : $1\n");
            }
            if (!$is_root && $line =~ /Address\s+([\da-fA-F.]+)/i) {
                out("  Root MAC        : $1\n");
            }
            if ($line =~ /Number of topology changes\s+(\d+)/i) {
                my $tc = $1;
                out("  Topology Changes: $tc");
                out($tc > 50 ? "  <-- WARNING: possible instability\n" : "\n");
            }
            if ($line =~ /\b(?:BLK|BLOCKING|BKN|inconsistent)\b/i) {
                (my $trimmed = $line) =~ s/^\s+//;
                push @blocked_ports, $trimmed;
            }
        }

        if (@blocked_ports) {
            out("\n  Blocked/Inconsistent Ports (" . scalar(@blocked_ports) . "):\n");
            out("    $_\n") for @blocked_ports;
        } else {
            out("  Blocked Ports   : none detected\n");
        }

        if ($vlan) {
            $ssh->send("show spanning-tree vlan $vlan detail");
            my $detail = $ssh->waitfor('\s*[>#]', $timeout) or die "Timeout on stp detail\n";
            for my $line (split /\n/, $detail) {
                out("  ALERT: $line\n") if $line =~ /(dispute|loop|inconsisten)/i;
            }
        }

        $ssh->send("exit");
    };

    if ($@) {
        (my $err = $@) =~ s/\s+$//;
        out("  ERROR: $err\n");
        return 0;
    }
    return 1;
}

my ($ok, $fail) = (0, 0);
for my $dev (@devices) {
    audit_stp($dev) ? $ok++ : $fail++;
}

out("\n--- Summary: $ok OK, $fail failed ---\n");
close $log_fh if $log_fh;
exit($fail ? 1 : 0);