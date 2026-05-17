The write permission was denied. The task asks to "Output ONLY the script content" — here it is:

#!/usr/bin/perl
#
# stp_audit.pl - Spanning Tree Protocol Audit Tool
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches via SSH and audits the STP topology.
#   Reports root bridge identity per VLAN, port roles/states, topology change
#   counters, and flags potential issues (TCN storms, inconsistent ports,
#   ports stuck in non-forwarding states).
#
# Usage:
#   ./stp_audit.pl <host>                    # single device
#   ./stp_audit.pl -f devices.txt            # batch from file (one IP per line)
#   ./stp_audit.pl <host> -l stp_audit.log   # with log file
#   ./stp_audit.pl <host> -v 10,20,100       # audit specific VLANs only
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH key auth or set NETDEV_PASS env variable for password auth
#   NETDEV_USER env variable (default: admin)
#
# Output:
#   Per-device summary: STP mode, root bridge, port count by state,
#   topology change stats, and any flagged anomalies.

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config pass_through);
use POSIX qw(strftime);

my $user     = $ENV{NETDEV_USER} || 'admin';
my $pass     = $ENV{NETDEV_PASS} || '';
my $timeout  = 20;
my $logfile  = '';
my $devfile  = '';
my $vlans    = '';

GetOptions(
    'f=s' => \$devfile,
    'l=s' => \$logfile,
    'v=s' => \$vlans,
);

my @hosts = $devfile ? read_hosts($devfile) : @ARGV;
die "Usage: $0 <host> [-f file] [-l logfile] [-v vlan_list]\n" unless @hosts;

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open logfile $logfile: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=== STP Audit started $ts ===\n", $log_fh);

for my $host (@hosts) {
    audit_device($host, $user, $pass, $timeout, $vlans, $log_fh);
}

close($log_fh) if $log_fh;

sub audit_device {
    my ($host, $user, $pass, $timeout, $vlans, $log_fh) = @_;

    output("\n--- Device: $host ---\n", $log_fh);

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $host,
            user        => $user,
            password    => $pass,
            raw_pty     => 1,
            timeout     => $timeout,
            ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
    };
    if ($@) {
        output("ERROR: Failed to create SSH session for $host: $@\n", $log_fh);
        return;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !$login) {
        output("ERROR: Authentication failed for $host\n", $log_fh);
        return;
    }

    $ssh->exec("terminal length 0");

    my $stp_sum = $ssh->exec("show spanning-tree summary");
    if (!$stp_sum) {
        output("ERROR: No response from $host — timed out\n", $log_fh);
        return;
    }

    my ($mode) = $stp_sum =~ /Switch is in (\S+(?:\s+\S+)?)\s+mode/i;
    $mode //= 'unknown';
    output("STP Mode : $mode\n", $log_fh);

    my $stp_detail = $vlans
        ? $ssh->exec("show spanning-tree vlan $vlans")
        : $ssh->exec("show spanning-tree");

    parse_and_report($stp_detail, $log_fh);

    my $tcn_output = $ssh->exec("show spanning-tree detail | include ieee|occur|topology");
    report_tcn($tcn_output, $log_fh);

    $ssh->close();
}

sub parse_and_report {
    my ($output, $log_fh) = @_;
    return unless $output;

    my (%root_by_vlan, %port_states);
    my $current_vlan = '';

    for my $line (split /\n/, $output) {
        if ($line =~ /^VLAN(\d+)\s*$/ || $line =~ /Spanning tree enabled.*VLAN\s*(\d+)/i) {
            $current_vlan = $1;
        }
        if ($line =~ /This bridge is the root/i && $current_vlan) {
            $root_by_vlan{$current_vlan} = 'THIS DEVICE';
        }
        if ($line =~ /Root ID.*Priority\s+(\d+)/i || $line =~ /Root\s+\S+\s+\d+\s+([\da-f]{4}\.[\da-f]{4}\.[\da-f]{4})/i) {
            $root_by_vlan{$current_vlan} //= $1 if $current_vlan;
        }
        if ($line =~ /^\s+(\S+)\s+(Root|Desg|Altn|Back|BLK|FWD|LIS|LRN|Bkn)\s+(FWD|BLK|LIS|LRN|BKN)\s/i) {
            my ($port, $role, $state) = ($1, uc($2), uc($3));
            $port_states{$state}++;
            if ($state =~ /^(BLK|BKN|LIS|LRN)$/ && $role eq 'DESG') {
                output("WARN : Port $port role=DESG state=$state — check for topology issue\n", $log_fh);
            }
            if ($line =~ /Incon/i) {
                output("WARN : Port $port in inconsistent state\n", $log_fh);
            }
        }
    }

    for my $vlan (sort { $a <=> $b } keys %root_by_vlan) {
        output(sprintf("VLAN %-5s Root: %s\n", $vlan, $root_by_vlan{$vlan}), $log_fh);
    }

    for my $state (sort keys %port_states) {
        output(sprintf("Ports %-4s: %d\n", $state, $port_states{$state}), $log_fh);
    }
}

sub report_tcn {
    my ($output, $log_fh) = @_;
    return unless $output;

    while ($output =~ /(\d+)\s+topology change(?:s)?\s+(?:occurred|detected)/gi) {
        my $count = $1;
        if ($count > 50) {
            output("WARN : High topology change count ($count) — possible TCN storm\n", $log_fh);
        } else {
            output("Info : Topology changes: $count\n", $log_fh);
        }
    }
}

sub read_hosts {
    my ($file) = @_;
    open(my $fh, '<', $file) or die "Cannot open device file $file: $!\n";
    my @hosts = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close($fh);
    return @hosts;
}

sub output {
    my ($msg, $log_fh) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}