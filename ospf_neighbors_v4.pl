#!/usr/bin/perl
# =============================================================================
# stp_audit.pl - Spanning Tree Protocol Status Auditor
# =============================================================================
# PURPOSE:
#   Audits Spanning Tree Protocol (STP) state on Cisco IOS/IOS-XE switches.
#   Identifies root bridges per VLAN, detects topology change storms, flags
#   blocking ports, and surfaces instability indicators that precede outages.
#
# USAGE:
#   perl stp_audit.pl -h <host> [-u user] [-p pass] [-e enable] [-l logfile]
#   perl stp_audit.pl -f <device_list.txt> [-u user] [-p pass] [-l logfile]
#
# PREREQUISITES:
#   cpan install Expect
#   cpan install Getopt::Long
#
# EXAMPLES:
#   perl stp_audit.pl -h 10.0.0.1 -u netops -p s3cr3t
#   perl stp_audit.pl -f switches.txt -u admin -l /var/log/stp_audit.log
#
# OUTPUT:
#   Per-device summary: STP mode, VLAN count, root ownership, topology change
#   totals, and flagged anomalies (high TC counts, unexpected root bridges).
# =============================================================================

use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($opt_host, $opt_user, $opt_pass, $opt_enable, $opt_file, $opt_log, $opt_help);
my $timeout      = 30;
my $tc_threshold = 5;

GetOptions(
    'h|host=s'   => \$opt_host,
    'u|user=s'   => \$opt_user,
    'p|pass=s'   => \$opt_pass,
    'e|enable=s' => \$opt_enable,
    'f|file=s'   => \$opt_file,
    'l|log=s'    => \$opt_log,
    'timeout=i'  => \$timeout,
    'help'       => \$opt_help,
);

if ($opt_help || (!$opt_host && !$opt_file)) {
    print "Usage: $0 -h <host> [-u user] [-p pass] [-e enable_pass] [-l logfile]\n";
    print "       $0 -f <device_list> [-u user] [-p pass] [-l logfile]\n";
    exit 0;
}

$opt_user   //= $ENV{NET_USER} // 'admin';
$opt_enable //= '';
unless ($opt_pass) {
    print "Password: ";
    system('stty', '-echo');
    chomp($opt_pass = <STDIN>);
    system('stty', 'echo');
    print "\n";
}

my @hosts = $opt_host ? ($opt_host) : ();
if ($opt_file) {
    open(my $fh, '<', $opt_file) or die "Cannot open $opt_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*[#;]/ || /^\s*$/; push @hosts, $_; }
    close $fh;
}

my $log_fh;
if ($opt_log) {
    open($log_fh, '>>', $opt_log) or die "Cannot open log $opt_log: $!\n";
    $log_fh->autoflush(1);
}

sub out { print "$_[0]\n"; print $log_fh "$_[0]\n" if $log_fh; }

out("=" x 62);
out("STP Audit  " . strftime('%Y-%m-%d %H:%M:%S', localtime));
out("=" x 62);

for my $device (@hosts) { audit_device($device); }
close $log_fh if $log_fh;
exit 0;

# --------------------------------------------------------------------------

sub audit_device {
    my ($device) = @_;
    out("\n[Device: $device]");

    my $exp = Expect->new();
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${opt_user}\@${device}")) {
        out("  ERROR: spawn failed — $!");
        return;
    }

    my $connected = $exp->expect($timeout,
        [ qr/[Pp]assword:/,  sub { $exp->send("$opt_pass\n"); exp_continue } ],
        [ qr/yes\/no\)/i,    sub { $exp->send("yes\n");       exp_continue } ],
        [ qr/[>#]/,          sub { 1 } ],
        [ 'timeout',         sub { 0 } ],
        [ 'eof',             sub { 0 } ],
    );

    unless ($connected) {
        out("  ERROR: Connection failed (timeout or auth error)");
        $exp->soft_close();
        return;
    }

    $exp->send("terminal length 0\n");
    $exp->expect($timeout, qr/[>#]/);

    if (($exp->before() // '') =~ />$/ || ($exp->match() // '') eq '>') {
        $exp->send("enable\n");
        $exp->expect($timeout,
            [ qr/[Pp]assword:/i, sub { $exp->send("$opt_enable\n"); exp_continue } ],
            [ qr/#/,             sub { } ],
        );
    }

    $exp->send("show spanning-tree summary totals\n");
    $exp->expect($timeout * 2, qr/#/);
    my $summary = $exp->before() // '';

    $exp->send("show spanning-tree detail | include ieee|occur|VLAN|is executing|We are\n");
    $exp->expect($timeout * 3, qr/#/);
    my $detail = $exp->before() // '';

    $exp->send("exit\n");
    $exp->soft_close();

    parse_results($device, $summary, $detail);
}

sub parse_results {
    my ($device, $summary, $detail) = @_;

    my $mode = 'unknown';
    $mode = $1 if $summary =~ /Switch\s+is\s+in\s+(\S+)\s+mode/i;
    $mode = $1 if $summary =~ /Spanning\s+tree\s+enabled\s+protocol\s+(\S+)/i;

    my ($blocking, $forwarding, $stp_active) = (0, 0, 0);
    $blocking   = $1 if $summary =~ /(\d+)\s+Blocking/i;
    $forwarding = $1 if $summary =~ /(\d+)\s+Forwarding/i;
    $stp_active = $1 if $summary =~ /(\d+)\s+active/i;

    my ($tc_total, $root_vlans) = (0, 0);
    my @issues;

    while ($detail =~ /VLAN(\d+)\b.*?(\d+)\s+topology\s+change/gsi) {
        my ($vlan, $tc) = ($1, $2);
        $tc_total += $tc;
        push @issues, "VLAN$vlan: $tc topology changes (threshold=$tc_threshold)" if $tc > $tc_threshold;
    }

    $root_vlans = () = ($detail =~ /We\s+are\s+the\s+root/gi);

    out("  STP mode       : $mode");
    out("  VLANs active   : $stp_active");
    out("  Root bridges   : $root_vlans VLAN(s) owned by this switch");
    out("  Ports fwding   : $forwarding   blocking: $blocking");
    out("  Total TC count : $tc_total");

    if (@issues) {
        out("  [!] Anomalies detected:");
        out("      - $_") for @issues;
    } elsif ($tc_total == 0 && $stp_active > 0) {
        out("  [OK] No topology change storms detected");
    }

    unless ($stp_active) {
        out("  [i] No active STP instances found — verify STP is enabled");
    }
}