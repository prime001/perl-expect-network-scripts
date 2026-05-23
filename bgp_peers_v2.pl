```perl
#!/usr/bin/perl
# =============================================================================
# bgp_prefix_monitor.pl - BGP Prefix Limit and Advertisement Audit
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers and audits BGP neighbor prefix
#   counts against configured prefix limits. Flags sessions approaching
#   their maximum-prefix threshold (default: 80%) to prevent unexpected
#   session drops due to prefix limit exhaustion.
#
# Usage:
#   ./bgp_prefix_monitor.pl <device_ip> [username] [password]
#   ./bgp_prefix_monitor.pl --file devices.txt [--log output.log]
#   ./bgp_prefix_monitor.pl --file devices.txt --threshold 75
#
# Prerequisites:
#   cpanm Net::SSH::Expect
#
# Output:
#   STDOUT + optional log file. Exits non-zero if any peer exceeds threshold.
#
# Author: Erik Anderson
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($device_file, $log_file, $threshold, $username, $password);
$threshold = 80;

GetOptions(
    'file=s'      => \$device_file,
    'log=s'       => \$log_file,
    'threshold=i' => \$threshold,
    'user=s'      => \$username,
    'pass=s'      => \$password,
) or die "Usage: $0 <device> [--file file] [--log file] [--threshold pct]\n";

$username //= $ENV{NET_USER} // 'admin';
$password //= $ENV{NET_PASS} // die "Set NET_PASS or pass --pass\n";

my @devices;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    @devices = grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
    close $fh;
} elsif (@ARGV) {
    @devices = ($ARGV[0]);
} else {
    die "Provide a device IP or --file devices.txt\n";
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

my $ts        = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $exit_code = 0;

sub out {
    my $msg = shift;
    print $msg;
    print {$log_fh} $msg if $log_fh;
}

out("=" x 70 . "\n");
out("BGP Prefix Limit Audit  |  $ts  |  Threshold: ${threshold}%\n");
out("=" x 70 . "\n");

for my $host (@devices) {
    out("\n[+] Connecting to $host...\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $host,
            user        => $username,
            password    => $password,
            raw_pty     => 1,
            timeout     => 15,
            ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
    };
    if ($@) {
        out("    ERROR: Failed to create SSH session: $@\n");
        $exit_code = 1;
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        out("    ERROR: Authentication failed for $host\n");
        $exit_code = 1;
        next;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('>#', 5);

    $ssh->send("show bgp summary\n");
    my $summary = $ssh->waitfor('>#', 30) // '';

    $ssh->send("show running-config | section ^router bgp\n");
    my $bgp_config = $ssh->waitfor('>#', 30) // '';

    $ssh->send("exit\n");

    # Parse neighbor IPs and their current prefix counts from summary
    my %peer_prefixes;
    for my $line (split /\n/, $summary) {
        # Cisco BGP summary: IP Ver AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
        if ($line =~ /^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\d+)/) {
            $peer_prefixes{$1} = { asn => $2, received => $3, limit => 0, warn_pct => 0 };
        }
    }

    # Parse max-prefix limits from running config
    my $current_neighbor = '';
    for my $line (split /\n/, $bgp_config) {
        if ($line =~ /neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+maximum-prefix\s+(\d+)/) {
            my ($ip, $limit) = ($1, $2);
            if (exists $peer_prefixes{$ip} && $limit > 0) {
                $peer_prefixes{$ip}{limit}    = $limit;
                $peer_prefixes{$ip}{warn_pct} = int($peer_prefixes{$ip}{received} / $limit * 100);
            }
        }
    }

    # Report
    out(sprintf "\n  %-18s %-8s %10s %10s %8s  %s\n",
        'Neighbor', 'ASN', 'Rcvd Pfx', 'Max Pfx', 'Usage', 'Status');
    out("  " . "-" x 65 . "\n");

    my $flagged = 0;
    for my $ip (sort keys %peer_prefixes) {
        my $p      = $peer_prefixes{$ip};
        my $limit  = $p->{limit} || 'none';
        my $pct    = $p->{limit} ? $p->{warn_pct} : 0;
        my $status = 'OK';

        if ($p->{limit} && $pct >= $threshold) {
            $status    = "WARN: ${pct}% of limit";
            $exit_code = 1;
            $flagged++;
        } elsif (!$p->{limit}) {
            $status = 'no max-prefix set';
        }

        out(sprintf "  %-18s %-8s %10s %10s %7s%%  %s\n",
            $ip, $p->{asn}, $p->{received}, $limit,
            ($p->{limit} ? $pct : '-'), $status);
    }

    if (!%peer_prefixes) {
        out("  No established BGP peers found or BGP not running.\n");
    } elsif ($flagged) {
        out("\n  *** $flagged peer(s) at or above ${threshold}% prefix limit ***\n");
    } else {
        out("\n  All peers within prefix limits.\n");
    }
}

out("\n" . "=" x 70 . "\n");
out("Audit complete. Exit code: $exit_code\n");
close $log_fh if $log_fh;
exit $exit_code;
```