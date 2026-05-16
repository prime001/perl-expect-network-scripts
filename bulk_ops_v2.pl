The user's explicit instruction — output only the script content — takes precedence over the brainstorming skill. Writing the spanning tree audit script now.

#!/usr/bin/perl
#
# spanning_tree_audit.pl — Bulk Spanning Tree Protocol Audit Tool
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches via SSH and audits spanning tree
#   status: root bridge placement, blocking ports, topology change counters,
#   and TCN storm indicators. Flags anything that warrants review.
#
# Usage:
#   ./spanning_tree_audit.pl -f devices.txt [-u user] [-p pass] [-l out.log]
#   ./spanning_tree_audit.pl -d 192.168.1.1  [-u user] [-p pass]
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#   SSH access with at least 'show' privilege on target devices.
#
# Device file format (one entry per line, # for comments):
#   192.168.1.1
#   sw-core-02
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($device_file, $single_device, $username, $password, $log_file);
my $timeout = 30;

GetOptions(
    'f=s' => \$device_file,
    'd=s' => \$single_device,
    'u=s' => \$username,
    'p=s' => \$password,
    'l=s' => \$log_file,
    't=i' => \$timeout,
) or die "Usage: $0 -f devices.txt | -d device [-u user] [-p pass] [-l logfile]\n";

die "Specify -f devices.txt or -d device\n" unless $device_file || $single_device;

$username ||= $ENV{NET_USER} || do { print "Username: "; chomp(my $u = <STDIN>); $u };
$password ||= $ENV{NET_PASS} || do {
    system('stty -echo');
    print "Password: ";
    chomp(my $p = <STDIN>);
    system('stty echo');
    print "\n";
    $p;
};

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $log_fh;
if ($log_file) {
    open($log_fh, '>', $log_file) or die "Cannot open log '$log_file': $!\n";
}

sub out {
    print @_;
    print $log_fh @_ if $log_fh;
}

sub audit_device {
    my ($host) = @_;

    out("\n" . ('=' x 60) . "\n");
    out("Host: $host\n");
    out('=' x 60, "\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $username,
        password => $password,
        timeout  => $timeout,
        raw_pty  => 1,
    );

    eval { $ssh->login() };
    if ($@) {
        out("  ERROR: Login failed — $@\n");
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('[>#]\s*$', 5);

    $ssh->send("show spanning-tree summary\n");
    my $summary = $ssh->waitfor('[>#]\s*$', $timeout) // '';

    $ssh->send("show spanning-tree detail\n");
    my $detail = $ssh->waitfor('[>#]\s*$', $timeout) // '';

    $ssh->send("exit\n");

    analyze($host, $summary, $detail);
}

sub analyze {
    my ($host, $summary, $detail) = @_;

    my @warnings;

    my @root_vlans;
    push @root_vlans, $1 while $summary =~ /VLAN(\d+)/gi
        && $summary =~ /root\s+bridge\s+for[^:]*VLAN(\d+)/gi;
    @root_vlans = ($summary =~ /Root bridge for[^:]*:\s*([^\n]+)/i)
        ? split(/,\s*/, $1) : ();

    my @blocking;
    push @blocking, $1 while $detail =~ /^\s*((?:Gi|Fa|Te|Hu|Et|Po)\S+)\s+\S+\s+BLK/mg;

    my ($tc_total) = $detail =~ /Number of topology changes\s+(\d+)/i;
    my ($tc_since) = $detail =~ /last change occurred\s+(\S+)\s+ago/i;

    if (defined $tc_total && $tc_total > 100) {
        push @warnings, sprintf("High topology change count: %d (last: %s ago)",
            $tc_total, $tc_since // 'unknown');
    }

    if ($summary =~ /portfast\s+bpduguard\s+default/i) {
        # good — BPDU guard globally enabled, no warning
    } elsif ($summary !~ /bpduguard/i) {
        push @warnings, "BPDU Guard not globally enabled";
    }

    out("  Root bridge for: " . (@root_vlans ? join(', ', @root_vlans) : 'none detected') . "\n");
    out("  Blocking ports:  " . (@blocking   ? join(', ', @blocking)   : 'none') . "\n");
    out("  TC count:        " . (defined $tc_total ? $tc_total : 'n/a') . "\n");
    out("  Last TC:         " . ($tc_since // 'n/a') . " ago\n");

    if (@warnings) {
        out("  WARNINGS:\n");
        out("    ! $_\n") for @warnings;
        out("  Status: REVIEW\n");
    } else {
        out("  Status: OK\n");
    }
}

my @devices;
if ($single_device) {
    push @devices, $single_device;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open '$device_file': $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*[#;]/ || /^\s*$/;
        push @devices, (split)[0];
    }
    close $fh;
}

die "No devices to audit.\n" unless @devices;

out("Spanning Tree Audit — $timestamp\n");
out("Devices: " . scalar(@devices) . "\n");

audit_device($_) for @devices;

out("\nDone. " . scalar(@devices) . " device(s) audited.\n");
close $log_fh if $log_fh;