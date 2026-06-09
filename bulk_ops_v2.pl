#!/usr/bin/perl
#
# spanning_tree_audit.pl - Spanning Tree Protocol topology audit
#
# Purpose:
#   Audits STP state across Cisco IOS/IOS-XE switches. Reports the root
#   bridge MAC per VLAN, flags when the polled device is itself the root,
#   and lists any ports currently in BLK state. Use this after topology
#   changes, new switch deployments, or when troubleshooting L2 loops.
#
# Usage:
#   ./spanning_tree_audit.pl -u USER -p PASS [options] host1 [host2 ...]
#   ./spanning_tree_audit.pl -u USER -p PASS -f device_list.txt
#
# Options:
#   -u, --user    SSH username (required)
#   -p, --pass    SSH password (required)
#   -f, --file    File of device IPs/hostnames, one per line (# = comment)
#   -l, --log     Append results to this logfile
#   -t, --timeout SSH/command timeout in seconds (default: 30)
#
# Prerequisites:
#   cpanm Net::SSH::Expect
#   SSH access enabled on target devices
#   Cisco IOS or IOS-XE with 802.1D/w/s spanning tree
#
# Example:
#   ./spanning_tree_audit.pl -u netops -p s3cret \
#       -l /var/log/stp_audit.log 10.1.1.1 10.1.1.2 10.1.1.3

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($user, $pass, $device_file, $logfile);
my $timeout = 30;

GetOptions(
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'f|file=s'    => \$device_file,
    'l|log=s'     => \$logfile,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -u USER -p PASS [-f file | host ...] [-l logfile]\n";

die "ERROR: -u (username) and -p (password) are required\n" unless $user && $pass;

my @devices;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open '$device_file': $!\n";
    while (<$fh>) { chomp; s/#.*//; next unless /\S/; push @devices, $_; }
    close $fh;
}
push @devices, @ARGV;
die "ERROR: No devices specified. Pass hostnames as args or use -f.\n" unless @devices;

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile
        or warn "Cannot open logfile '$logfile': $! (logging disabled)\n";
}

sub out {
    my ($line) = @_;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=" x 58);
out("STP Audit  |  $ts");
out(sprintf("Devices: %d  |  Timeout: %ds", scalar(@devices), $timeout));
out("=" x 58);

my ($ok, $fail) = (0, 0);

for my $host (@devices) {
    out("\n[$host]");

    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        user       => $user,
        password   => $pass,
        raw_pty    => 1,
        timeout    => $timeout,
        log_stdout => 0,
    );

    my $login;
    eval { $login = $ssh->login() };
    if ($@ || !defined $login) {
        (my $err = $@ // 'unknown error') =~ s/\n/ /g;
        out("  FAIL  connection error: $err");
        $fail++;
        next;
    }
    if ($login =~ /[Dd]enied|[Ii]ncorrect|[Ff]ail/i) {
        out("  FAIL  authentication rejected");
        $fail++;
        next;
    }

    $ssh->exec("terminal length 0");

    my $raw = $ssh->exec("show spanning-tree");
    if (!defined $raw || length($raw) < 20) {
        out("  FAIL  no output from 'show spanning-tree'");
        $ssh->close();
        $fail++;
        next;
    }

    my (%roots, %blocked);
    my ($cur_vlan, $in_root) = (undef, 0);

    for my $line (split /\n/, $raw) {
        if ($line =~ /^VLAN(\d+)/) {
            $cur_vlan = int($1);
            $in_root  = 0;
            next;
        }
        next unless defined $cur_vlan;

        $in_root = 1 if $line =~ /\bRoot\s+ID\b/;
        $in_root = 0 if $line =~ /\bBridge\s+ID\b/;

        if ($in_root && $line =~ /Address\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})/) {
            $roots{$cur_vlan}{mac} = lc $1;
        }
        if ($line =~ /This bridge is the root/) {
            $roots{$cur_vlan}{local_root} = 1;
        }
        if ($line =~ /^\s*((?:Gi|Fa|Te|Eth|Po)\S+)\s+\S+\s+BLK\b/i) {
            push @{$blocked{$cur_vlan}}, $1;
        }
    }

    if (!%roots) {
        out("  INFO  no STP VLANs detected (STP disabled or access-only uplink)");
    }

    for my $vlan (sort { $a <=> $b } keys %roots) {
        my $mac  = $roots{$vlan}{mac}        // 'unknown';
        my $flag = $roots{$vlan}{local_root} ? '  <-- THIS SWITCH IS ROOT' : '';
        out(sprintf("  VLAN %-5d  root %s%s", $vlan, $mac, $flag));
        if (my @blk = @{$blocked{$vlan} // []}) {
            out("             blocked: " . join(', ', @blk));
        }
    }

    $ssh->close();
    $ok++;
}

out("\n" . "=" x 58);
out("Done: $ok succeeded, $fail failed");
close $log_fh if $log_fh;