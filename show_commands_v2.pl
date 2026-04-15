#!/usr/bin/perl
# =============================================================================
# qos_stats.pl - QoS Policy-Map Statistics Collector
# =============================================================================
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE devices via SSH and collects
#   QoS policy-map interface statistics. Parses class-map drop counters and
#   queue depth to surface active congestion and policy violations. Useful
#   for capacity planning, SLA verification, and performance troubleshooting.
#
# Usage:
#   Single device:   perl qos_stats.pl -h 192.168.1.1 -u admin -p secret
#   Device list:     perl qos_stats.pl -f devices.txt -u admin -p secret
#   With log file:   perl qos_stats.pl -h 192.168.1.1 -u admin -p secret -l qos.log
#   Drop threshold:  perl qos_stats.pl -h 192.168.1.1 -u admin -p secret -d 1000
#
# Prerequisites:
#   cpan install Net::SSH::Expect Getopt::Long
#
# Device file format: one IP/hostname per line, lines starting with # ignored
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $logfile, $drop_threshold);
my $timeout = 30;
$drop_threshold = 0;

GetOptions(
    'h|host=s'      => \$host,
    'f|file=s'      => \$device_file,
    'u|user=s'      => \$username,
    'p|pass=s'      => \$password,
    'l|log=s'       => \$logfile,
    'd|drops=i'     => \$drop_threshold,
    't|timeout=i'   => \$timeout,
) or die "Usage: $0 -h host|-f file -u user -p pass [-l logfile] [-d drop_threshold]\n";

die "Must specify -h host or -f device_file\n" unless $host || $device_file;
die "Must specify -u username\n" unless $username;
die "Must specify -p password\n" unless $password;

my @devices;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open logfile $logfile: $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
output("=" x 70);
output("QoS Policy-Map Statistics Report - $timestamp");
output("Drop threshold filter: $drop_threshold packets");
output("=" x 70);

for my $device (@devices) {
    output("\n--- Device: $device ---");
    eval { collect_qos_stats($device) };
    if ($@) {
        my $err = $@;
        $err =~ s/\n/ /g;
        output("ERROR [$device]: $err");
    }
}

close $log_fh if $log_fh;
exit 0;

sub collect_qos_stats {
    my ($target) = @_;

    my $ssh = Net::SSH::Expect->new(
        host        => $target,
        user        => $username,
        password    => $password,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login = eval { $ssh->login() };
    if (!$login || $login =~ /[Pp]assword|[Dd]enied|[Ff]ailed/) {
        die "Authentication failed for $target";
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('>\s*$|#\s*$', 5);

    $ssh->send("show policy-map interface");
    my $raw = $ssh->waitfor('#\s*$', $timeout);

    $ssh->send("exit");
    $ssh->close();

    if (!$raw || $raw =~ /Invalid input|% Error/) {
        output("  No QoS policy-maps applied or command unsupported");
        return;
    }

    parse_policymap_output($target, $raw);
}

sub parse_policymap_output {
    my ($target, $raw) = @_;

    my ($current_iface, $current_policy, $current_class);
    my %flagged;
    my $found_any = 0;

    for my $line (split /\n/, $raw) {
        $line =~ s/\r//g;

        if ($line =~ /^([A-Za-z][A-Za-z0-9\/\.\-]+)\s*$/) {
            $current_iface = $1;
        }

        if ($line =~ /Service-policy\s+(?:output|input):\s+(\S+)/) {
            $current_policy = $1;
            $found_any = 1;
        }

        if ($line =~ /Class-map:\s+(\S+)/) {
            $current_class = $1;
        }

        if ($line =~ /(\d+)\s+packets.*?(\d+)\s+(?:bytes\s+)?(?:dropped|tail drops)/) {
            my ($pkts, $bytes) = ($1, $2);
            if ($pkts > $drop_threshold && $current_class && $current_policy) {
                my $key = "$current_iface/$current_policy/$current_class";
                unless ($flagged{$key}++) {
                    output(sprintf("  DROPS  iface=%-25s policy=%-20s class=%-20s drops=%s pkts",
                        $current_iface // 'unknown',
                        $current_policy // 'unknown',
                        $current_class,
                        $pkts));
                }
            }
        }

        if ($line =~ /(\d+)\s+packets output.*?(\d+)\s+drops/) {
            my ($out, $drops) = ($1, $2);
            if ($drops > $drop_threshold && $current_class) {
                output(sprintf("  QUEUE  iface=%-25s class=%-20s output=%s drops=%s",
                    $current_iface // 'unknown', $current_class, $out, $drops));
            }
        }
    }

    output("  No policy-maps with drops above threshold ($drop_threshold)") unless %flagged;
    output("  No QoS policy-maps found on this device") unless $found_any;
}

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}