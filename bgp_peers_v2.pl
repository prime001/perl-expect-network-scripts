#!/usr/bin/perl
# =============================================================================
# bgp_prefix_limit_monitor.pl — BGP Prefix-Limit Health Check
#
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE routers and compares each BGP
#   neighbor's current received-prefix count against its configured maximum-
#   prefix limit.  Peers at or above a warning threshold (default 80%) are
#   flagged so the operator can act before the session gets torn down.
#
# Usage:
#   Single device:   perl bgp_prefix_limit_monitor.pl -h 10.0.0.1
#   Device file:     perl bgp_prefix_limit_monitor.pl -f devices.txt
#   Custom threshold: add -t 75   (warn at 75 %)
#   Log to file:     add -l /var/log/bgp_prefix_check.log
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH key-based auth recommended; password auth supported via -p flag.
#
# Output:
#   OK / WARN / CRIT per neighbor, plus a summary line per device.
#   Exit code 0 = all OK, 1 = at least one WARN, 2 = at least one CRIT.
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# ---------------------------------------------------------------------------
# CLI options
# ---------------------------------------------------------------------------
my ($host, $device_file, $username, $password, $log_file);
my $warn_pct = 80;

GetOptions(
    'h=s' => \$host,
    'f=s' => \$device_file,
    'u=s' => \$username,
    'p=s' => \$password,
    't=i' => \$warn_pct,
    'l=s' => \$log_file,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-t warn%] [-l logfile]\n";

$username //= $ENV{NET_USER} // 'admin';
die "No device specified. Use -h or -f.\n" unless $host || $device_file;

my @devices = $host ? ($host) : do {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
};

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub logprint {
    my $msg = strftime("[%Y-%m-%d %H:%M:%S] ", localtime) . $_[0] . "\n";
    print $msg;
    print $log_fh $msg if $log_fh;
}

# ---------------------------------------------------------------------------
# Per-device check
# ---------------------------------------------------------------------------
my $global_exit = 0;

for my $device (@devices) {
    logprint("=== $device ===");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $device,
            user        => $username,
            ($password ? (password => $password) : ()),
            raw_pty     => 1,
            timeout     => 15,
        );
    };
    if ($@ || !$ssh) {
        logprint("ERROR $device: connection failed — $@");
        $global_exit = 2 if $global_exit < 2;
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        logprint("ERROR $device: authentication failed");
        $global_exit = 2 if $global_exit < 2;
        next;
    }

    # Disable paging so we get full output in one shot
    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\#', 5);

    $ssh->send("show bgp neighbors | include BGP neighbor|Prefixes Current|Maximum prefix\n");
    my $raw = $ssh->waitfor('\#', 30) // '';

    $ssh->send("exit\n");

    # -------------------------------------------------------------------
    # Parse output — pull neighbor IP, current prefix count, max-prefix
    # -------------------------------------------------------------------
    my ($current_neighbor, %data);
    for my $line (split /\r?\n/, $raw) {
        if ($line =~ /BGP neighbor is (\S+)/) {
            $current_neighbor = $1;
            $current_neighbor =~ s/,$//;
        }
        # "  Prefixes Current:          45"  (IOS-XE style)
        if ($current_neighbor && $line =~ /Prefixes Current:\s+(\d+)/) {
            $data{$current_neighbor}{current} = $1;
        }
        # "  Maximum prefix limit:    100"  or  "maximum 100 ..."
        if ($current_neighbor && $line =~ /[Mm]aximum.*?(\d+)/) {
            $data{$current_neighbor}{max} //= $1;
        }
    }

    if (!%data) {
        logprint("INFO $device: no BGP neighbors found or no prefix-limit configured");
        next;
    }

    my ($ok, $warn, $crit) = (0, 0, 0);
    for my $nbr (sort keys %data) {
        my $cur = $data{$nbr}{current} // 0;
        my $max = $data{$nbr}{max};

        unless (defined $max && $max > 0) {
            logprint("INFO $device neighbor $nbr: current=$cur  max=unlimited");
            next;
        }

        my $pct = int($cur / $max * 100);
        my $status;
        if ($pct >= 100) {
            $status = 'CRIT';
            $crit++;
            $global_exit = 2 if $global_exit < 2;
        } elsif ($pct >= $warn_pct) {
            $status = 'WARN';
            $warn++;
            $global_exit = 1 if $global_exit < 1;
        } else {
            $status = 'OK  ';
            $ok++;
        }
        logprint("$status $device neighbor $nbr: $cur/$max prefixes ($pct%)");
    }

    logprint("SUMMARY $device: OK=$ok WARN=$warn CRIT=$crit");
}

close $log_fh if $log_fh;
exit $global_exit;