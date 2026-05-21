#!/usr/bin/perl
#
# bgp_prefix_monitor.pl - BGP Prefix Limit Monitor for Cisco IOS/IOS-XE
#
# Purpose:
#   Connects to one or more routers and checks each BGP neighbor's current
#   prefix count against its configured maximum-prefix limit. Flags neighbors
#   approaching or exceeding thresholds, and reports neighbors with no limit
#   configured (a common misconfiguration that can cause table explosion).
#
# Usage:
#   ./bgp_prefix_monitor.pl 10.0.0.1
#   ./bgp_prefix_monitor.pl -f devices.txt -l /var/log/bgp_prefix.log
#   ./bgp_prefix_monitor.pl -u admin -p secret -w 75 -c 90 10.0.0.1 10.0.0.2
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH access to devices; set ROUTER_USER / ROUTER_PASS or use -u/-p flags
#
# Output columns: Neighbor | AS | Prefixes | MaxPrefix | Pct | Status
#   Status values: OK / WARNING (>=warn%) / CRITICAL (>=crit%) / NO-LIMIT / DOWN
#
# Exit code: 0=all OK, 1=warnings present, 2=critical/no-limit present

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($user, $pass, $file, $logfile, $warn_pct, $crit_pct, $help);
$warn_pct = 80;
$crit_pct = 95;

GetOptions(
    'u|user=s'  => \$user,
    'p|pass=s'  => \$pass,
    'f|file=s'  => \$file,
    'l|log=s'   => \$logfile,
    'w|warn=i'  => \$warn_pct,
    'c|crit=i'  => \$crit_pct,
    'h|help'    => \$help,
) or die "Option error. Use -h for usage.\n";

if ($help) {
    print "Usage: $0 [-u user] [-p pass] [-f file] [-l log] [-w 80] [-c 95] [host...]\n";
    exit 0;
}

$user //= $ENV{ROUTER_USER} // 'admin';
$pass //= $ENV{ROUTER_PASS} or die "Password required: set ROUTER_PASS env var or use -p\n";

my @devices;
if ($file) {
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if $_; }
    close $fh;
}
push @devices, @ARGV;
die "No devices specified. Use -f FILE or pass hosts as arguments.\n" unless @devices;

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!\n";
}

my $ts       = strftime("%Y-%m-%d %H:%M:%S", localtime);
my $worst    = 0;

sub emit {
    my $line = shift;
    print $line;
    print $log_fh $line if $log_fh;
}

sub check_device {
    my $host = shift;
    emit("=" x 68 . "\n");
    emit("Device: $host   [$ts]\n");
    emit(sprintf("  %-18s %-8s %10s %10s %7s  %s\n",
        "Neighbor","AS","Prefixes","MaxPrefix","Pct","Status"));
    emit("  " . "-" x 62 . "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $host,
            user     => $user,
            password => $pass,
            raw_pty  => 1,
            timeout  => 15,
        );
    };
    unless ($ssh && !$@) {
        emit("  ERROR: Cannot create SSH session: $@\n\n");
        $worst = 2;
        return;
    }

    my $login = eval { $ssh->login() };
    if ($@ || ($login // '') =~ /[Dd]enied|[Ff]ailed|[Ii]nvalid/) {
        emit("  ERROR: Authentication failed\n\n");
        $worst = 2;
        $ssh->close() if $ssh;
        return;
    }

    $ssh->send("terminal length 0\n");  $ssh->waitfor('\#|\$', 10);

    $ssh->send("show ip bgp summary\n");
    my $summary = $ssh->waitfor('\#|\$', 20) // '';

    $ssh->send("show run | section router bgp\n");
    my $config = $ssh->waitfor('\#|\$', 20) // '';

    $ssh->send("exit\n");
    $ssh->close();

    my %max_pfx;
    while ($config =~ /neighbor\s+(\S+)\s+maximum-prefix\s+(\d+)/g) {
        $max_pfx{$1} = $2;
    }

    my $found = 0;
    for my $line (split /\n/, $summary) {
        next unless $line =~ /^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\d+\s+\d+\s+\S+\s+(\S+)/;
        my ($nbr, $as, $state_pfx) = ($1, $2, $3);
        $found++;

        my ($pfx, $status, $pct_str);
        if ($state_pfx =~ /^\d+$/) {
            $pfx = $state_pfx;
            my $max = $max_pfx{$nbr} // 0;
            if ($max > 0) {
                my $pct = ($pfx / $max) * 100;
                $pct_str = sprintf("%.1f%%", $pct);
                if ($pct >= $crit_pct) {
                    $status = "CRITICAL"; $worst = 2 if $worst < 2;
                } elsif ($pct >= $warn_pct) {
                    $status = "WARNING";  $worst = 1 if $worst < 1;
                } else {
                    $status = "OK";
                }
                emit(sprintf("  %-18s %-8s %10d %10d %7s  %s\n",
                    $nbr, $as, $pfx, $max, $pct_str, $status));
            } else {
                $status = "NO-LIMIT"; $worst = 2 if $worst < 2;
                emit(sprintf("  %-18s %-8s %10d %10s %7s  %s\n",
                    $nbr, $as, $pfx, "none", "N/A", $status));
            }
        } else {
            $status = "DOWN ($state_pfx)";
            emit(sprintf("  %-18s %-8s %10s %10s %7s  %s\n",
                $nbr, $as, "-", $max_pfx{$nbr} // "none", "-", $status));
        }
    }
    emit("  No BGP neighbors found.\n") unless $found;
    emit("\n");
}

check_device($_) for @devices;
close $log_fh if $log_fh;
exit $worst;