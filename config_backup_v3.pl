#!/usr/bin/perl
# =============================================================================
# stp_audit.pl - Spanning Tree Protocol Audit Tool
#
# Purpose: Connects to Cisco IOS/IOS-XE switches via SSH and collects STP
#          state including root bridge status, port roles, topology change
#          counters, and BPDU guard configuration. Flags elevated topology
#          change counts that indicate instability or misconfigured ports.
#
# Usage:
#   ./stp_audit.pl -h <host> [-u <user>] [-p <pass>] [-e <enable>] [-l <log>]
#   ./stp_audit.pl -f <device_file> [-u <user>] [-p <pass>] [-l <logfile>]
#
# Device file format: one IP/hostname per line; lines beginning with # skipped
#
# Credentials fallback: NET_USER / NET_PASS environment variables
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $username, $password, $enable_pass, $logfile);
my $timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'e|enable=s'  => \$enable_pass,
    'l|log=s'     => \$logfile,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h <host>|-f <file> [-u user] [-p pass] [-e enable] [-l logfile]\n";

die "Specify -h <host> or -f <file>\n" unless $host || $file;

$username //= $ENV{NET_USER} // 'admin';
$password //= $ENV{NET_PASS} // die "Password required: use -p or set NET_PASS\n";

my @devices;
if ($file) {
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    while (<$fh>) { chomp; next if /^\s*[#\s]*$/; push @devices, $_; }
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_stp {
    my ($device) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);

    out("\n" . "=" x 68 . "\n");
    out("Device: $device  |  $ts\n");
    out("=" x 68 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $username,
        password => $password,
        raw_pty  => 1,
        timeout  => $timeout,
    );

    eval {
        my $out = $ssh->login();
        die "Unexpected prompt after login\n" unless $out =~ /[>#]/;
    };
    if ($@) {
        out("ERROR [$device]: $@");
        return;
    }

    if ($enable_pass) {
        $ssh->send('enable');
        $ssh->waitfor('Password:', $timeout);
        $ssh->send($enable_pass);
        $ssh->waitfor('[#]', $timeout);
    }

    $ssh->exec('terminal length 0');

    # STP mode and root bridge summary
    my $summary = $ssh->exec('show spanning-tree summary') // '';
    my ($mode) = $summary =~ /Switch is in (\S+ \S+) mode/;
    $mode //= 'unknown';
    my $root_vlans = () = $summary =~ /Root bridge for/g;
    out(sprintf("STP mode: %-20s  Root for %d VLAN(s)\n", $mode, $root_vlans));
    out("WARNING: Active topology change in progress\n") if $summary =~ /topology change/i;

    # Topology change counters and port states
    my $detail = $ssh->exec('show spanning-tree detail | include topology|Root ID|is root|Blocked') // '';
    my $tc_total = 0;
    $tc_total += $1 while $detail =~ /topology changes? (\d+)/gi;
    my $blocked  = () = $detail =~ /BLK|Blocking/gi;
    out(sprintf("Topology changes (all instances): %-8d  Blocking ports: %d\n", $tc_total, $blocked));
    out("ALERT: Topology change count $tc_total exceeds threshold - investigate instability\n") if $tc_total > 100;

    # Port role summary
    my $ifaces = $ssh->exec('show spanning-tree | include DESG|ROOT|ALTN|BACK') // '';
    my $desg = () = $ifaces =~ /DESG/g;
    my $root = () = $ifaces =~ /ROOT/g;
    my $altn = () = $ifaces =~ /ALTN|BACK/g;
    out(sprintf("Port roles  ->  Designated: %d  Root: %d  Alternate/Backup: %d\n", $desg, $root, $altn));

    # BPDU guard global state
    my $bpdu = $ssh->exec('show spanning-tree summary | include BPDU') // '';
    if ($bpdu =~ /BPDU Guard\s+:\s+enabled/i) {
        out("BPDU Guard: enabled globally\n");
    } else {
        out("BPDU Guard: NOT enabled globally (check per-port)\n");
    }

    # Root bridge for each active VLAN
    out("\nActive STP instances:\n");
    my $instances = $ssh->exec('show spanning-tree | include ^VLAN|This bridge is|Root ID') // '';
    my @lines = split /\n/, $instances;
    my $vlan = '';
    for my $line (@lines) {
        if ($line =~ /^(VLAN\S+)/) { $vlan = $1; }
        elsif ($line =~ /This bridge is the root/i) { out("  $vlan: THIS SWITCH IS ROOT\n"); }
        elsif ($line =~ /Root ID.*Priority\s+(\d+)/) { out("  $vlan: upstream root priority $1\n"); }
    }

    $ssh->close();
    out("Done: $device\n");
}

out("STP Audit started: " . strftime('%Y-%m-%d %H:%M:%S', localtime) . "\n");
out("Processing " . scalar(@devices) . " device(s)\n");

audit_stp($_) for @devices;

out("\n" . "=" x 68 . "\n");
out("Audit complete.  " . scalar(@devices) . " device(s) processed.\n");
close $log_fh if $log_fh;