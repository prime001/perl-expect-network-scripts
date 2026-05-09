#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# stp_audit.pl - Spanning Tree Protocol Health Audit
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches and audits STP topology health:
#   checks root bridge placement, port states, topology change counts,
#   and flags anomalies that indicate instability or misconfiguration.
#
# Usage:
#   perl stp_audit.pl -h 192.168.1.1 -u admin -p secret [-v <vlan>] [-l logfile]
#   perl stp_audit.pl -f device_list.txt -u admin -p secret
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH enabled on target devices
#   Account with at least 'show' privilege
#
# Output:
#   Per-VLAN root bridge, topology change count, and port state summary.
#   Flags VLANs with TC count > 10 (potential instability).
# =============================================================================

my ($host, $user, $pass, $vlan_filter, $logfile, $device_file);
my $timeout = 30;
my $tc_threshold = 10;

GetOptions(
    'h|host=s'     => \$host,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'v|vlan=s'     => \$vlan_filter,
    'l|log=s'      => \$logfile,
    'f|file=s'     => \$device_file,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h HOST -u USER -p PASS [-v VLAN] [-l LOGFILE]\n";

die "Must supply credentials: -u USER -p PASS\n" unless $user && $pass;
die "Must supply -h HOST or -f FILE\n" unless $host || $device_file;

my @devices = $host ? ($host) : do {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    my @list = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
    @list;
};

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log $logfile: $!\n";
}

sub output {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my $device = shift;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    output("\n[$ts] === STP Audit: $device ===\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password     => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        output("  ERROR: SSH connection failed to $device: $@\n");
        return;
    }
    if ($login_output =~ /[Aa]uth|[Dd]enied|[Ff]ail/) {
        output("  ERROR: Authentication failed on $device\n");
        return;
    }

    # Disable paging
    $ssh->send("terminal length 0\n");
    $ssh->waitfor('[\$#>]\s*$', 5);

    my $cmd = $vlan_filter ? "show spanning-tree vlan $vlan_filter"
                           : "show spanning-tree";
    $ssh->send("$cmd\n");
    my $output = $ssh->waitfor('[\$#>]\s*$', $timeout);

    unless ($output) {
        output("  ERROR: No response from $device\n");
        return;
    }

    my ($current_vlan, %results);

    for my $line (split /\n/, $output) {
        if ($line =~ /^VLAN(\d+)/) {
            $current_vlan = $1;
            $results{$current_vlan} = { root => 'unknown', tc => 0, ports => [] };
        }
        next unless $current_vlan;

        if ($line =~ /This bridge is the root/) {
            $results{$current_vlan}{root} = 'THIS SWITCH (root bridge)';
        } elsif ($line =~ /Root ID.*Priority.*\n.*Address\s+(\S+)/s) {
            $results{$current_vlan}{root} = $1;
        } elsif ($line =~ /Root\s+\S+\s+(\d+)\s+(\S+)/) {
            $results{$current_vlan}{root} ||= $2;
        } elsif ($line =~ /Number of topology changes\s+(\d+)/) {
            $results{$current_vlan}{tc} = $1;
        } elsif ($line =~ /^\s+(\S+)\s+(Root|Desg|Altn|Back|BLK|FWD|LRN|LIS)\s+(FWD|BLK|LRN|LIS|BKN)\s+/) {
            push @{$results{$current_vlan}{ports}}, "$1: $2/$3";
        }
    }

    if (!%results) {
        output("  No STP data found (no VLANs active or parse error)\n");
        return;
    }

    my $issues = 0;
    for my $vlan (sort { $a <=> $b } keys %results) {
        my $r = $results{$vlan};
        my $flag = $r->{tc} > $tc_threshold ? " *** HIGH TC COUNT ***" : "";
        $issues++ if $flag;
        output(sprintf("  VLAN %-5s  Root: %-20s  TC: %4d%s\n",
            $vlan, $r->{root}, $r->{tc}, $flag));
        if (@{$r->{ports}}) {
            output("    Ports: " . join(', ', @{$r->{ports}}) . "\n");
        }
    }

    my $vlan_count = scalar keys %results;
    output(sprintf("  Summary: %d VLANs audited, %d with TC count > %d\n",
        $vlan_count, $issues, $tc_threshold));
}

for my $device (@devices) {
    audit_device($device);
}

close $log_fh if $log_fh;
output("\nAudit complete.\n");