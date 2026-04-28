#!/usr/bin/perl
#
# stp_audit.pl - Spanning Tree Protocol Root Bridge and Port State Audit
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches via SSH and audits the STP topology
#   per VLAN. Identifies root bridges, flags unexpected root elections, and
#   reports blocking port counts. Useful for verifying STP convergence after
#   topology changes or validating a reference root bridge across the fleet.
#
# Usage:
#   ./stp_audit.pl -h <host> [-u user] [-p pass] [-r root_mac] [-l logfile]
#   ./stp_audit.pl -f <device_file> [-u user] [-p pass] [-r root_mac] [-l logfile]
#
# Options:
#   -h <host>      Single device IP or hostname
#   -f <file>      File with one device per line (# lines are comments)
#   -u <user>      SSH username (default: SSH_USER env, then 'admin')
#   -p <pass>      SSH password (default: SSH_PASS env)
#   -r <root_mac>  Expected root bridge MAC (e.g. 0011.2233.4455); warns if any
#                  VLAN has a different root
#   -l <logfile>   Append output to this file in addition to STDOUT
#
# Prerequisites:
#   Perl modules: Expect, Getopt::Long
#   SSH access with privilege level sufficient for 'show spanning-tree'
#   Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x
#
# Exit codes: 0=clean, 1=warnings (unexpected root), 2=connection errors

use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $expected_root, $logfile);
my $timeout = 30;

GetOptions(
    'h=s' => \$host,
    'f=s' => \$device_file,
    'u=s' => \$username,
    'p=s' => \$password,
    'r=s' => \$expected_root,
    'l=s' => \$logfile,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-r root_mac] [-l logfile]\n";

$username ||= $ENV{SSH_USER} || 'admin';
$password ||= $ENV{SSH_PASS} or die "Error: password required via -p or SSH_PASS env\n";

my @devices;
if ($host) {
    @devices = ($host);
} elsif ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open '$device_file': $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
} else {
    die "Error: specify -h <host> or -f <file>\n";
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log '$logfile': $!\n";
}

my $stamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=" x 68);
out("STP Root Bridge Audit  --  $stamp");
out("=" x 68);

my ($total, $ok_count, $warn_count, $err_count) = (0, 0, 0, 0);

for my $device (@devices) {
    $total++;
    out("\n--- $device ---");

    my $exp = Expect->new();
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -l $username $device")) {
        out("  ERROR: spawn failed: $!");
        $err_count++;
        next;
    }

    my $authed = 0;
    $exp->expect($timeout,
        [ qr/[Pp]assword:\s*/      => sub { $exp->send("$password\n"); exp_continue; } ],
        [ qr/[>#]\s*$/             => sub { $authed = 1; } ],
        [ qr/[Dd]enied|[Ff]ailed/ => sub { out("  ERROR: authentication failed"); } ],
        [ timeout                  => sub { out("  ERROR: connection timed out"); } ],
    );

    unless ($authed) {
        $exp->soft_close();
        $err_count++;
        next;
    }

    $exp->send("terminal length 0\n");
    $exp->expect($timeout, qr/[>#]\s*$/);

    $exp->send("show spanning-tree summary\n");
    my $summary = '';
    $exp->expect($timeout,
        [ qr/[>#]\s*$/ => sub { $summary = $exp->before(); } ],
        [ timeout       => sub { out("  ERROR: timeout on summary command"); } ],
    );

    $exp->send("show spanning-tree root\n");
    my $root_out = '';
    $exp->expect($timeout,
        [ qr/[>#]\s*$/ => sub { $root_out = $exp->before(); } ],
        [ timeout       => sub { out("  ERROR: timeout on root command"); } ],
    );

    $exp->send("exit\n");
    $exp->soft_close();

    if ($summary =~ /Switch is in (\S+) mode/i) {
        out("  STP mode: $1");
    }

    # Parse "show spanning-tree root" tabular output
    # Columns: Root ID | Priority | MAC | Hello | MaxAge | FwdDly | Interface
    my $device_warn = 0;
    my @rows;
    for my $line (split /\n/, $root_out) {
        next unless $line =~ /^VLAN(\d+)\s+\d+\s+([0-9a-f.]{14})\s+\d+\s+\d+\s+\d+\s*(\S*)/i;
        my ($vid, $mac, $port) = ($1, lc $2, $3 || 'local (this sw is root)');
        my $flag = '';
        if ($expected_root && lc($expected_root) ne $mac) {
            $flag = '  <-- UNEXPECTED ROOT';
            $device_warn = 1;
        }
        push @rows, sprintf("  VLAN %-5s  root %-17s  via %-22s%s", $vid, $mac, $port, $flag);
    }

    if (@rows) {
        out($_) for @rows;
    } else {
        out("  No STP VLAN data found (no active VLANs or unsupported output format)");
    }

    if ($summary =~ /(\d+)\s+forwarding\s+(\d+)\s+blocking/i ||
        $summary =~ /(\d+)\s+in\s+STP\s+forwarding.*?(\d+)\s+in\s+STP\s+blocking/si) {
        out("  Ports -- forwarding: $1  blocking: $2");
    }

    if ($device_warn) { $warn_count++; } else { $ok_count++; }
}

out("\n" . "=" x 68);
out(sprintf("Done: %d devices | clean: %d | root warnings: %d | errors: %d",
    $total, $ok_count, $warn_count, $err_count));
out("=" x 68);

close $log_fh if $log_fh;
exit($err_count ? 2 : $warn_count ? 1 : 0);

sub out {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}