```perl
#!/usr/bin/perl
#
# bgp_prefix_audit.pl - BGP Prefix Limit Compliance Auditor
#
# Purpose:
#   Audits BGP neighbors for prefix count vs configured max-prefix limits.
#   Flags neighbors approaching or exceeding thresholds. Distinct from
#   bgp_peers.pl (session state) -- this script focuses on prefix volume
#   analysis and limit compliance, useful for capacity planning and
#   preventing unexpected session teardowns.
#
# Usage:
#   ./bgp_prefix_audit.pl <device_ip> [options]
#   ./bgp_prefix_audit.pl --file devices.txt [options]
#
# Options:
#   --user <username>   SSH username (default: $USER or 'admin')
#   --pass <password>   SSH password (prompted if omitted)
#   --warn <pct>        Warn threshold as % of prefix limit (default: 75)
#   --crit <pct>        Critical threshold as % of prefix limit (default: 90)
#   --log <file>        Append results to log file
#   --timeout <sec>     SSH command timeout (default: 30)
#   --help              Show this help
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   Device must permit: show bgp summary, show bgp neighbors
#
# Tested against: Cisco IOS 15.x, IOS-XE 16.x/17.x
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Term::ReadKey;
use POSIX qw(strftime);

my ($help, $device_file, $log_file);
my $username = $ENV{USER} || 'admin';
my $password = '';
my $warn_pct = 75;
my $crit_pct = 90;
my $timeout  = 30;

GetOptions(
    'help'       => \$help,
    'file=s'     => \$device_file,
    'user=s'     => \$username,
    'pass=s'     => \$password,
    'warn=i'     => \$warn_pct,
    'crit=i'     => \$crit_pct,
    'log=s'      => \$log_file,
    'timeout=i'  => \$timeout,
) or die "Invalid options. Use --help.\n";

if ($help) {
    open(my $fh, '<', $0) or die;
    while (<$fh>) { last unless /^#/; print substr($_, 2) }
    close $fh;
    exit 0;
}

my @devices;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    @devices = grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
    close $fh;
} elsif (@ARGV) {
    @devices = @ARGV;
} else {
    die "Usage: $0 <device_ip> [options] or $0 --file devices.txt\n";
}

unless ($password) {
    print "SSH password for $username: ";
    ReadMode('noecho');
    chomp($password = <STDIN>);
    ReadMode('restore');
    print "\n";
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

sub log_output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my ($host) = @_;
    my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);

    log_output("\n=== BGP Prefix Audit: $host @ $timestamp ===\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $username,
        password => $password,
        timeout  => $timeout,
        raw_pty  => 1,
    );

    eval {
        $ssh->login();
        $ssh->exec("terminal length 0");

        my $summary = $ssh->exec("show bgp summary");
        unless ($summary && $summary =~ /Neighbor\s+V\s+AS/i) {
            log_output("  [ERROR] BGP not configured or no summary available\n");
            return;
        }

        my %neighbors;
        while ($summary =~ /^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)/mg) {
            $neighbors{$1} = { asn => $2, prefixes_received => $3, max_prefix => 0 };
        }

        if (!%neighbors) {
            log_output("  No active BGP neighbors found\n");
            return;
        }

        foreach my $peer (sort keys %neighbors) {
            my $detail = $ssh->exec("show bgp neighbors $peer");

            if ($detail =~ /Maximum prefix:\s*(\d+)/i) {
                $neighbors{$peer}{max_prefix} = $1;
            }
        }

        my ($ok, $warn, $crit) = (0, 0, 0);
        log_output(sprintf("  %-18s %-8s %-12s %-12s %-8s %s\n",
            "Neighbor", "ASN", "Prefixes", "Max-Prefix", "Usage%", "Status"));
        log_output("  " . "-" x 70 . "\n");

        foreach my $peer (sort keys %neighbors) {
            my $rcvd = $neighbors{$peer}{prefixes_received};
            my $max  = $neighbors{$peer}{max_prefix};
            my $asn  = $neighbors{$peer}{asn};
            my ($pct_str, $status);

            if ($max > 0) {
                my $pct = int(($rcvd / $max) * 100);
                $pct_str = "$pct%";
                if ($pct >= $crit_pct)       { $status = "CRITICAL"; $crit++ }
                elsif ($pct >= $warn_pct)    { $status = "WARNING";  $warn++ }
                else                         { $status = "OK";       $ok++   }
            } else {
                $pct_str = "N/A";
                $status  = "NO-LIMIT";
                $ok++;
            }

            log_output(sprintf("  %-18s %-8s %-12s %-12s %-8s %s\n",
                $peer, $asn, $rcvd, ($max || "none"), $pct_str, $status));
        }

        log_output("\n  Summary: " . scalar(keys %neighbors) .
            " neighbors | OK=$ok WARN=$warn CRIT=$crit\n");
    };

    if ($@) {
        my $err = $@;
        $err =~ s/\n/ /g;
        log_output("  [ERROR] $host: $err\n");
    }

    $ssh->close() if $ssh;
}

audit_device($_) for @devices;

log_output("\nAudit complete.\n");
close $log_fh if $log_fh;
```