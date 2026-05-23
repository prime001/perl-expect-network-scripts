The repo path wasn't specified as a local directory — I'll output the script content directly as requested.

```
#!/usr/bin/perl
#
# stp_audit.pl - Spanning Tree Protocol topology audit for Cisco IOS switches
#
# Purpose:
#   Connects to one or more Cisco IOS switches via SSH and collects STP state.
#   Identifies root bridge placement, reports ports in BLOCKING state, and flags
#   high topology-change counts that indicate instability. Use before/after
#   maintenance windows or during network triage.
#
# Usage:
#   ./stp_audit.pl -h <host> [-u user] [-p pass] [-l logfile]
#   ./stp_audit.pl -f <hosts_file> [-u user] [-p pass] [-l logfile]
#
#   Credentials fall back to NET_USER / NET_PASS environment variables.
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH must be enabled on target devices; key-based auth recommended.
#
# Output:
#   Per-device summary: VLANs where switch is root, topology change count,
#   and any ports in BLOCKING state with associated VLAN.

use strict;
use warnings;
use Getopt::Long;
use Net::SSH::Expect;
use POSIX qw(strftime);

my ($host, $hosts_file, $username, $password, $logfile);
$username = $ENV{NET_USER} // 'admin';
$password = $ENV{NET_PASS} // '';

GetOptions(
    'h|host=s'   => \$host,
    'f|file=s'   => \$hosts_file,
    'u|user=s'   => \$username,
    'p|pass=s'   => \$password,
    'l|log=s'    => \$logfile,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile]\n";

die "ERROR: Specify -h <host> or -f <file>\n" unless $host || $hosts_file;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $hosts_file or die "ERROR: Cannot open $hosts_file: $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
    die "ERROR: No valid hosts found in $hosts_file\n" unless @devices;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "ERROR: Cannot open logfile $logfile: $!\n";
}

sub out {
    print $_[0];
    print $log_fh $_[0] if $log_fh;
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=" x 60 . "\n");
out("STP Audit Report -- $ts\n");
out("=" x 60 . "\n\n");

for my $dev (@devices) {
    out("Device: $dev\n");
    out("-" x 40 . "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $dev,
            user     => $username,
            password => $password,
            raw_pty  => 1,
            timeout  => 15,
        );
    };
    if ($@ || !$ssh) {
        out("  ERROR: Could not create SSH session -- $@\n\n");
        next;
    }

    my $logged_in = eval { $ssh->login() };
    if ($@ || !$logged_in) {
        out("  ERROR: Authentication failed or connection refused\n\n");
        next;
    }

    $ssh->exec("terminal length 0");

    my $summary = $ssh->exec("show spanning-tree summary") // '';
    my $detail  = $ssh->exec("show spanning-tree detail")  // '';
    $ssh->exec("exit");
    $ssh->close();

    my $root_vlans = 0;
    my $tc_count   = 0;
    $root_vlans = $1 if $summary =~ /(\d+)\s+vlans?\s+(?:are\s+)?participating\s+as\s+root/i;
    $tc_count   = $1 if $summary =~ /(\d+)\s+topology\s+changes/i;

    out(sprintf("  Root bridge for %d VLAN(s)\n", $root_vlans));
    out(sprintf("  Topology changes    : %d", $tc_count));
    out($tc_count > 100 ? "  <-- WARNING: possible port flap\n" : "\n");

    my %blocking;
    my $cur_vlan = '';
    for my $line (split /\n/, $detail) {
        $cur_vlan = $1 if $line =~ /VLAN(\d+)\s+is\s+executing/i;
        if ($cur_vlan && $line =~ /(\S+(?:Ethernet|thernet|channel)\S*)\s+of\s+\S+\s+is\s+BLK/i) {
            push @{$blocking{$cur_vlan}}, $1;
        }
    }

    if (%blocking) {
        out("  Blocking ports:\n");
        for my $vlan (sort { $a <=> $b } keys %blocking) {
            out(sprintf("    VLAN %-5s  %s\n", $vlan, join(', ', @{$blocking{$vlan}})));
        }
    } else {
        out("  No ports in BLOCKING state\n");
    }

    out("\n");
}

out("Audit complete.\n");
close $log_fh if $log_fh;
```