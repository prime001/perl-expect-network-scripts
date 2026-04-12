#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# spanning_tree_audit.pl
#
# Purpose:
#   Audits Spanning Tree Protocol (STP) topology on Cisco IOS/IOS-XE switches.
#   Collects root bridge status, port roles/states, and flags non-designated
#   ports and topology change counts that may indicate instability.
#
# Usage:
#   ./spanning_tree_audit.pl --host <ip|hostname> [--user <username>]
#                            [--pass <password>] [--vlan <vlan_id>]
#                            [--file <device_list>] [--log <logfile>]
#
# Prerequisites:
#   - Perl modules: Net::SSH::Expect, Getopt::Long
#   - SSH access to target device(s)
#   - User account with at minimum 'show' privilege (level 1)
#
# Examples:
#   ./spanning_tree_audit.pl --host 10.1.1.1 --user neteng --pass s3cr3t
#   ./spanning_tree_audit.pl --file switches.txt --vlan 100 --log stp_audit.log
# =============================================================================

my ($opt_host, $opt_user, $opt_pass, $opt_vlan, $opt_file, $opt_log);
$opt_user = 'admin';
$opt_vlan = '';

GetOptions(
    'host=s' => \$opt_host,
    'user=s' => \$opt_user,
    'pass=s' => \$opt_pass,
    'vlan=s' => \$opt_vlan,
    'file=s' => \$opt_file,
    'log=s'  => \$opt_log,
) or die "Usage: $0 --host <host> [--user <u>] [--pass <p>] [--vlan <v>] [--file <f>] [--log <l>]\n";

unless ($opt_pass) {
    print "Password: ";
    system('stty', '-echo');
    chomp($opt_pass = <STDIN>);
    system('stty', 'echo');
    print "\n";
}

my @devices;
if ($opt_file) {
    open(my $fh, '<', $opt_file) or die "Cannot open device file '$opt_file': $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
} elsif ($opt_host) {
    push @devices, $opt_host;
} else {
    die "Must specify --host or --file\n";
}

my $log_fh;
if ($opt_log) {
    open($log_fh, '>>', $opt_log) or die "Cannot open log file '$opt_log': $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);

sub output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

output("=" x 70 . "\n");
output("STP Audit Report - $timestamp\n");
output("=" x 70 . "\n\n");

for my $host (@devices) {
    output("Host: $host\n");
    output("-" x 50 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $opt_user,
        password    => $opt_pass,
        raw_pty     => 1,
        timeout     => 15,
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        output("  ERROR: SSH login failed - $@\n\n");
        next;
    }

    if ($login_output =~ /assword/i) {
        output("  ERROR: Authentication failed for $host\n\n");
        next;
    }

    # Disable paging
    $ssh->send("terminal length 0");
    $ssh->waitfor('\$\s*#|\>\s*$', 5);

    my $stp_cmd = $opt_vlan ? "show spanning-tree vlan $opt_vlan" : "show spanning-tree summary";
    $ssh->send($stp_cmd);
    my $stp_output = $ssh->waitfor('#\s*$', 20);

    unless (defined $stp_output && $stp_output =~ /\w/) {
        output("  ERROR: No output received from '$stp_cmd'\n\n");
        $ssh->close();
        next;
    }

    # Parse root bridge status
    if ($stp_output =~ /This bridge is the root/i) {
        output("  Root Bridge: YES (this device is root)\n");
    } elsif ($stp_output =~ /Root ID.*?Address\s+([0-9a-f.]+)/si) {
        output("  Root Bridge: NO  (Root MAC: $1)\n");
    }

    # Parse topology changes
    if ($stp_output =~ /topology change count\s+(\d+)/i) {
        my $tc = $1;
        my $flag = $tc > 100 ? "  *** HIGH - possible instability ***" : "";
        output("  Topology Changes: $tc$flag\n");
    }

    # Parse port roles and flag non-forwarding ports
    my @blocking;
    my @root_ports;
    my @desg_ports;
    while ($stp_output =~ /(\S+)\s+(Root|Desg|Altn|Back|BLK|FWD|LIS|LRN)\s+(FWD|BLK|LIS|LRN)/gi) {
        my ($port, $role, $state) = ($1, $2, $3);
        push @blocking, $port  if $state =~ /BLK/i || $role =~ /Altn|Back/i;
        push @root_ports, $port if $role =~ /Root/i;
        push @desg_ports, $port if $role =~ /Desg/i;
    }

    output("  Root Ports:        " . (@root_ports ? join(', ', @root_ports) : 'none') . "\n");
    output("  Designated Ports:  " . (@desg_ports ? join(', ', @desg_ports) : 'none') . "\n");
    output("  Blocking/Alternate: " . (@blocking ? join(', ', @blocking) : 'none') . "\n");

    # Check for RSTP/PVST mode
    if ($stp_output =~ /(rapid-pvst|rstp|mstp|pvst)/i) {
        output("  STP Mode: $1\n");
    }

    $ssh->send("exit");
    $ssh->close();
    output("\n");
}

output("Audit complete.\n");
close $log_fh if $log_fh;