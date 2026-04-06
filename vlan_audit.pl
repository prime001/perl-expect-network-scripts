#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# 007_vlan_audit.pl - VLAN Audit Script for Cisco IOS/IOS-XE Switches
# =============================================================================
# Purpose:
#   Connects to one or more Cisco switches via SSH and collects VLAN data:
#   active VLANs, their names, trunk port assignments, and access port counts.
#   Useful for documenting switch environments, pre-change audits, and
#   detecting stale/unused VLANs across the network.
#
# Usage:
#   Single device:   ./007_vlan_audit.pl -h 192.168.1.1 -u admin -p secret
#   Device file:     ./007_vlan_audit.pl -f devices.txt -u admin -p secret
#   With log file:   ./007_vlan_audit.pl -f devices.txt -u admin -p secret -l vlan_audit.log
#
# Prerequisites:
#   Perl modules: Net::SSH::Expect, Getopt::Long
#   Install:      cpanm Net::SSH::Expect
#   Devices must have SSH enabled and the user needs privilege level 1 minimum.
#
# devices.txt format: one IP or hostname per line, blank lines/# comments OK
# =============================================================================

my ($host, $user, $pass, $device_file, $log_file, $timeout);
$timeout = 15;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'l|log=s'      => \$log_file,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOGFILE] [-t TIMEOUT]\n";

die "Provide -h HOST or -f FILE\n"  unless $host || $device_file;
die "Username required (-u)\n"      unless $user;
die "Password required (-p)\n"      unless $pass;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^\s*#/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
output("=" x 70);
output("VLAN Audit Report - $timestamp");
output("=" x 70);

for my $device (@devices) {
    output("\n--- Device: $device ---");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        output("  ERROR: SSH login failed for $device - $@");
        next;
    }
    if ($login_output =~ /[Pp]assword|[Aa]uth/i && $login_output !~ /[>#]/) {
        output("  ERROR: Authentication failed for $device");
        next;
    }

    # Disable paging
    $ssh->send("terminal length 0");
    $ssh->waitfor('\s*[>#]', $timeout) or do {
        output("  ERROR: No prompt after terminal length 0 on $device");
        next;
    };

    # Collect VLAN brief
    $ssh->send("show vlan brief");
    my $vlan_output = $ssh->waitfor('\s*[>#]', $timeout);
    unless (defined $vlan_output) {
        output("  ERROR: Timeout waiting for 'show vlan brief' output");
        next;
    }

    # Collect trunk info
    $ssh->send("show interfaces trunk");
    my $trunk_output = $ssh->waitfor('\s*[>#]', $timeout) // '';

    $ssh->send("exit");

    # Parse VLANs
    my %vlans;
    for my $line (split /\n/, $vlan_output) {
        next unless $line =~ /^\s*(\d+)\s+(\S+)\s+(active|act\/lshut|act\/unsup)/i;
        my ($id, $name, $status) = ($1, $2, $3);
        next if $id == 1002 || $id == 1003 || $id == 1004 || $id == 1005; # skip token ring/fddi
        $vlans{$id} = { name => $name, status => $status, trunks => [] };
    }

    # Parse trunk ports carrying each VLAN
    my @trunk_section;
    my $in_vlan_section = 0;
    for my $line (split /\n/, $trunk_output) {
        $in_vlan_section = 1 if $line =~ /VLANs allowed and active/i;
        next unless $in_vlan_section;
        if ($line =~ /^\s*(\S+)\s+([\d,\-]+)/) {
            my ($port, $vlan_list) = ($1, $2);
            for my $vid (expand_vlan_list($vlan_list)) {
                push @{$vlans{$vid}{trunks}}, $port if exists $vlans{$vid};
            }
        }
        last if $in_vlan_section && $line =~ /VLANs in spanning tree/i;
    }

    if (!%vlans) {
        output("  No active VLANs found (or parse error)");
        next;
    }

    output(sprintf("  %-6s %-32s %-12s %s", "VLAN", "Name", "Status", "Trunk Ports"));
    output("  " . "-" x 65);
    for my $vid (sort { $a <=> $b } keys %vlans) {
        my $v = $vlans{$vid};
        my $trunks = @{$v->{trunks}} ? join(',', @{$v->{trunks}}) : 'none';
        output(sprintf("  %-6s %-32s %-12s %s", $vid, $v->{name}, $v->{status}, $trunks));
    }
    output(sprintf("  Total active VLANs: %d", scalar keys %vlans));
}

output("\nAudit complete - " . strftime("%Y-%m-%d %H:%M:%S", localtime));
close $log_fh if $log_fh;

sub expand_vlan_list {
    my ($list) = @_;
    my @ids;
    for my $token (split /,/, $list) {
        if ($token =~ /^(\d+)-(\d+)$/) {
            push @ids, ($1..$2);
        } elsif ($token =~ /^(\d+)$/) {
            push @ids, $1;
        }
    }
    return @ids;
}

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}