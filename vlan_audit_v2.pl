#!/usr/bin/perl
# =============================================================================
# vlan_stp_audit.pl - Per-VLAN Spanning Tree Protocol Stability Audit
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches and audits spanning tree health
#   per VLAN. Identifies root bridge placement, blocked/alternate port counts,
#   and elevated topology change notifications (TCNs) that signal STP
#   instability. Useful for post-change validation and incident triage.
#
# Usage:
#   ./vlan_stp_audit.pl -h <host>                   single device
#   ./vlan_stp_audit.pl -f <hosts.txt>              bulk, one host per line
#
# Options:
#   -u <user>    SSH username      (default: $NET_USER or 'admin')
#   -p <pass>    SSH password      (default: $NET_PASS)
#   -l <file>    Append output to log file
#   -t <n>       TCN warning threshold, per VLAN (default: 50)
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH enabled on target, privilege level 1+ sufficient
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_log);
my $opt_user = $ENV{NET_USER} // 'admin';
my $opt_pass = $ENV{NET_PASS} // '';
my $opt_tcn  = 50;

GetOptions(
    'h|host=s' => \$opt_host,
    'f|file=s' => \$opt_file,
    'u|user=s' => \$opt_user,
    'p|pass=s' => \$opt_pass,
    'l|log=s'  => \$opt_log,
    't|tcn=i'  => \$opt_tcn,
) or die "Usage: $0 -h <host>|-f <file> [-u user] [-p pass] [-l logfile] [-t tcn_thresh]\n";

die "Specify -h <host> or -f <file>\n" unless $opt_host || $opt_file;

my @devices;
if ($opt_host) {
    @devices = ($opt_host);
} else {
    open my $fh, '<', $opt_file or die "Cannot open $opt_file: $!\n";
    @devices = map { chomp; $_ } grep { /\S/ && !/^\s*#/ } <$fh>;
}

my $log_fh;
if ($opt_log) {
    open $log_fh, '>>', $opt_log or die "Cannot open log $opt_log: $!\n";
}

sub out {
    print @_;
    print $log_fh @_ if $log_fh;
}

sub run_cmd {
    my ($ssh, $cmd, $timeout) = @_;
    $timeout //= 10;
    $ssh->send($cmd);
    return $ssh->waitfor('[\$#>]\s*$', $timeout) // '';
}

sub audit_host {
    my ($host) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    out "\n" . ('=' x 62) . "\n";
    out "Host: $host    $ts\n";
    out ('=' x 62) . "\n";

    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $opt_user,
        password => $opt_pass,
        raw_pty  => 1,
        timeout  => 20,
    );

    eval { $ssh->login() };
    if ($@) {
        out "ERROR: SSH login failed for $host: $@\n";
        return;
    }

    run_cmd($ssh, 'terminal length 0', 5);

    my $summary = run_cmd($ssh, 'show spanning-tree summary', 10);
    my $stp_mode = ($summary =~ /Switch is in (\S+)\s+mode/i) ? $1 : 'unknown';
    my $bpdu_guard = ($summary =~ /Portfast BPDU Guard Default\s+is enabled/i) ? 'enabled' : 'disabled';
    out sprintf("STP mode: %-12s  BPDU Guard default: %s\n", $stp_mode, $bpdu_guard);

    my $brief = run_cmd($ssh, 'show spanning-tree brief', 20);

    my (@root_vlans, @blocked_ports);
    my $cur_vlan = '';
    for my $line (split /\n/, $brief) {
        $cur_vlan = $1 if $line =~ /^(VLAN\d+)\b/;
        push @root_vlans, $cur_vlan if $line =~ /This bridge is the root/i && $cur_vlan;
        if ($line =~ /\b(?:Altn|BLK)\b/ && $cur_vlan) {
            my ($iface) = (split /\s+/, $line)[0];
            push @blocked_ports, "$cur_vlan/$iface" if $iface;
        }
    }

    out sprintf("Root bridge for %d VLAN(s)", scalar @root_vlans);
    if (@root_vlans && @root_vlans <= 20) {
        out ": " . join(' ', @root_vlans);
    } elsif (@root_vlans > 20) {
        out " (first 5: " . join(' ', @root_vlans[0..4]) . " ...)";
    }
    out "\n";

    if (@blocked_ports) {
        my $shown = join(', ', @blocked_ports[0 .. ($#blocked_ports < 8 ? $#blocked_ports : 8)]);
        out "Blocked/Altn ports: $shown";
        out " (+" . (@blocked_ports - 9) . " more)" if @blocked_ports > 9;
        out "\n";
    } else {
        out "Blocked ports: none\n";
    }

    my $detail = run_cmd($ssh, 'show spanning-tree detail | include VLAN|topology changes', 25);
    my (@tcn_warn);
    $cur_vlan = '';
    for my $line (split /\n/, $detail) {
        $cur_vlan = $1 if $line =~ /^(VLAN\d+)\s/;
        push @tcn_warn, "$cur_vlan(n=$1)"
            if $line =~ /Number of topology changes\s+(\d+)/i && $1 >= $opt_tcn && $cur_vlan;
    }

    if (@tcn_warn) {
        out "WARN: TCN >= $opt_tcn on: " . join(', ', @tcn_warn) . "\n";
    } else {
        out "TCN instability check: OK (threshold=$opt_tcn)\n";
    }

    $ssh->close();
    out "Done: $host\n";
}

for my $dev (@devices) {
    eval { audit_host($dev) };
    out "FATAL [$dev]: $@\n" if $@;
}

close $log_fh if $log_fh;