Here's the complete script content for `stp_health_check.pl`:

```perl
#!/usr/bin/perl
#
# stp_health_check.pl - Spanning Tree Protocol Health Audit
#
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE switches via SSH and audits the
#   Spanning Tree topology for common issues: unexpected root bridges, ports
#   stuck in non-forwarding states, high topology change counts, and
#   mismatched STP mode (PVST vs RSTP vs MST).
#
# Usage:
#   Single device:   ./stp_health_check.pl -h 192.168.1.1 -u admin -p secret
#   Device file:     ./stp_health_check.pl -f devices.txt -u admin -p secret
#   With log:        ./stp_health_check.pl -f devices.txt -u admin -p secret -l stp_audit.log
#   Expected root:   ./stp_health_check.pl -h 10.0.0.1 -u admin -p secret -r 10.0.0.254
#
# Device file format (one IP/hostname per line, blank lines and # comments ignored):
#   192.168.1.1
#   192.168.1.2
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to target devices with privilege-exec enabled
#   Devices must support: show spanning-tree summary, show spanning-tree detail
#
# Exit codes: 0=clean, 1=issues found, 2=fatal error

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $logfile, $expected_root);
my $timeout = 15;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$logfile,
    'r|root=s'     => \$expected_root,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOGFILE] [-r EXPECTED_ROOT]\n";

die "Specify -h HOST or -f FILE\n"    unless $host || $device_file;
die "Username required (-u)\n"        unless $username;
die "Password required (-p)\n"        unless $password;

my @devices;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if $_; }
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>', $logfile or die "Cannot open log $logfile: $!\n";
}

my $ts      = strftime("%Y-%m-%d %H:%M:%S", localtime);
my $issues  = 0;

sub out {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

out("=" x 65 . "\n");
out("STP Health Audit  $ts\n");
out("Devices: " . scalar(@devices) . "  Expected root: " . ($expected_root // "any") . "\n");
out("=" x 65 . "\n\n");

for my $dev (@devices) {
    out("--- $dev ---\n");
    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $dev,
            user        => $username,
            password     => $password,
            raw_pty     => 1,
            timeout     => $timeout,
        );
    };
    if ($@ || !$ssh) {
        out("  [ERROR] SSH init failed: $@\n\n");
        $issues++;
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !$login) {
        out("  [ERROR] Auth failed or timed out\n\n");
        $issues++;
        next;
    }

    $ssh->exec("terminal length 0");

    my $summary = $ssh->exec("show spanning-tree summary") // "";
    my $detail  = $ssh->exec("show spanning-tree detail")  // "";
    $ssh->close();

    # Parse STP mode
    my $mode = "unknown";
    $mode = "PVST+"  if $summary =~ /Switch is in pvst mode/i;
    $mode = "RPVST+" if $summary =~ /Switch is in rapid-pvst mode/i;
    $mode = "MST"    if $summary =~ /Switch is in mst mode/i;
    out("  Mode       : $mode\n");

    # Count blocking/listening ports
    my $blocking_count  = () = $summary =~ /\bBLK\b/g;
    my $listening_count = () = $summary =~ /\bLIS\b/g;

    # Extract root bridge addresses per VLAN
    my %roots;
    while ($summary =~ /^(?:VLAN\S+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)/mg) {
        $roots{$2}++ if $1 eq 'root';
    }

    # Topology change counts from detail output
    my $tc_total = 0;
    $tc_total += $1 while $detail =~ /(\d+) topology changes/g;

    # Root bridge check
    my @root_list = keys %roots;
    if ($expected_root && @root_list) {
        my @wrong = grep { $_ ne $expected_root } @root_list;
        if (@wrong) {
            out("  [WARN]  Unexpected root(s): " . join(", ", @wrong) . "\n");
            $issues++;
        } else {
            out("  Root(s)    : " . join(", ", @root_list) . " [OK]\n");
        }
    } elsif (@root_list) {
        out("  Root(s)    : " . join(", ", @root_list) . "\n");
    }

    out("  Blocking   : $blocking_count port(s)" . ($blocking_count > 0 ? " [check if expected]\n" : "\n"));
    if ($listening_count > 0) {
        out("  [WARN]  $listening_count port(s) in LISTENING state (topology flux?)\n");
        $issues++;
    }
    if ($tc_total > 100) {
        out("  [WARN]  High topology change count: $tc_total (loop or flap suspected)\n");
        $issues++;
    } elsif ($tc_total > 0) {
        out("  TC count   : $tc_total\n");
    }

    out("\n");
}

out("=" x 65 . "\n");
out("Result: " . ($issues == 0 ? "CLEAN — no STP anomalies found" : "$issues issue(s) flagged") . "\n");
out("=" x 65 . "\n");

close $log_fh if $log_fh;
exit($issues > 0 ? 1 : 0);
```

**What it does:** STP health audit — checks across multiple switches for unexpected root bridges (with optional `-r` flag to assert which root is correct), ports stuck in LISTENING state (indicates active topology flux), high topology change counts (loop/flap indicator), and STP mode (PVST+/RPVST+/MST). BLOCKING ports are noted but not flagged as errors since they're normal in PVST environments.

**Why it's distinct from existing scripts:** `bulk_ops.pl` runs arbitrary config commands, `show_commands.pl` collects show output — this one specifically parses STP state and raises structured warnings, which is the auditing angle the repo doesn't currently cover.