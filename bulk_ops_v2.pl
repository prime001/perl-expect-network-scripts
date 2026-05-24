Writing a Perl STP audit script — spanning tree root bridge and port state analysis isn't covered by any existing scripts in the repo.

```perl
#!/usr/bin/perl
#
# stp_audit.pl - Spanning Tree Protocol Root Bridge and Port State Auditor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH, collects spanning tree
#   status per VLAN, identifies root bridges, flags non-forwarding ports
#   (BLK/LIS/LRN), and reports cumulative topology change counts.
#   High topology change counts indicate L2 instability worth investigating.
#
# Usage:
#   Single device:  ./stp_audit.pl -h 192.168.1.1 [-u admin] [-p secret]
#   Device file:    ./stp_audit.pl -f devices.txt [-u admin] [-p secret]
#   With logging:   ./stp_audit.pl -f devices.txt -l /var/log/stp_audit.log
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH must be enabled on target devices (Cisco IOS-style CLI assumed)
#
# devices.txt format: one IP or hostname per line; lines starting with # skipped
#
# Environment variables: NET_USER, NET_PASS (override defaults; avoid -p on CLI)

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $logfile, $help);
my $timeout = 15;
my $tc_warn_threshold = 100;

GetOptions(
    'h|host=s'   => \$host,
    'f|file=s'   => \$file,
    'u|user=s'   => \$user,
    'p|pass=s'   => \$pass,
    'l|log=s'    => \$logfile,
    'timeout=i'  => \$timeout,
    'help'       => \$help,
) or usage();

usage() if $help || (!$host && !$file);

$user //= $ENV{NET_USER} // 'admin';
$pass //= $ENV{NET_PASS} // do {
    local $| = 1;
    print 'Password: ';
    my $p = <STDIN>;
    chomp $p;
    $p;
};

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $file or die "Cannot open device file '$file': $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*[#;]/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log '$logfile': $!\n";
}

out("=== STP Audit: " . strftime('%Y-%m-%d %H:%M:%S', localtime) . " ===\n");
out(sprintf("Devices: %d  |  Threshold for TC warning: %d changes\n\n",
    scalar @devices, $tc_warn_threshold));

my ($ok, $fail) = (0, 0);
for my $dev (@devices) {
    out("--- $dev ---\n");
    if (audit_stp($dev)) { $ok++ } else { $fail++ }
    out("\n");
}

out("=== Done: " . strftime('%Y-%m-%d %H:%M:%S', localtime)
    . "  OK=$ok  FAIL=$fail ===\n");
close $log_fh if $log_fh;
exit($fail ? 1 : 0);

sub audit_stp {
    my ($dev) = @_;

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $dev,
            user     => $user,
            password => $pass,
            raw_pty  => 1,
            timeout  => $timeout,
        );
    };
    if ($@) {
        out("  ERROR: object init failed: $@\n");
        return 0;
    }

    my $login_out = eval { $ssh->login() };
    if ($@ || !defined $login_out || $login_out =~ /incorrect|denied|failed/i) {
        out("  ERROR: login failed" . ($@ ? ": $@" : '') . "\n");
        return 0;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('[$#>]', $timeout);

    # Per-VLAN root bridge table
    $ssh->send('show spanning-tree root');
    my $root_out = $ssh->waitfor('[$#>]', $timeout) // '';

    my %vlan_root;
    for my $line (split /\n/, $root_out) {
        # VLAN0001   32769  aabb.cc00.0100   20  15  15  Gi0/1
        if ($line =~ /^(VLAN\d+)\s+\d+\s+(\S+:\S+|\S{4}\.\S{4}\.\S{4})\s+\d+\s+\d+\s+\d+\s+(\S+)/) {
            $vlan_root{$1} = { bridge => $2, root_port => $3 };
        }
    }

    if (%vlan_root) {
        out("  Root bridges:\n");
        for my $vlan (sort keys %vlan_root) {
            out(sprintf("    %-12s  bridge=%-20s  root_port=%s\n",
                $vlan, $vlan_root{$vlan}{bridge}, $vlan_root{$vlan}{root_port}));
        }
    } else {
        out("  Root bridges: no data (STP may be disabled or parse failed)\n");
    }

    # Non-forwarding ports
    $ssh->send('show spanning-tree | include BLK|LIS|LRN');
    my $nonfwd = $ssh->waitfor('[$#>]', $timeout) // '';

    my @blocked = grep { /\b(?:BLK|LIS|LRN)\b/ }
                  map  { s/^\s+|\s+$//gr }
                  split(/\n/, $nonfwd);

    if (@blocked) {
        out("  Non-forwarding ports (" . scalar(@blocked) . "):\n");
        out("    $_\n") for @blocked;
    } else {
        out("  Non-forwarding ports: none\n");
    }

    # Topology change count from summary
    $ssh->send('show spanning-tree summary totals');
    my $summary = $ssh->waitfor('[$#>]', $timeout) // '';

    my $tc_total = 0;
    $tc_total += $1 while $summary =~ /(\d+)\s+topology\s+change/gi;

    out("  Topology changes (cumulative): $tc_total\n");
    out("  WARNING: high topology change count - investigate L2 instability\n")
        if $tc_total > $tc_warn_threshold;

    $ssh->close();
    return 1;
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub usage {
    print <<'END';
Usage: stp_audit.pl -h <host> | -f <file> [options]

  -h, --host     Single device IP or hostname
  -f, --file     File listing devices, one per line (# = comment)
  -u, --user     SSH username (default: admin or \$NET_USER)
  -p, --pass     SSH password (default: \$NET_PASS or interactive prompt)
  -l, --log      Append output to log file
      --timeout  SSH timeout in seconds (default: 15)
      --help     Show this help

Exits 0 if all devices succeeded, 1 if any failed.
END
    exit 1;
}
```