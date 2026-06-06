#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# ospf_lsdb_audit.pl - OSPF Link State Database audit tool
#
# Purpose:
#   Audits the OSPF LSDB on Cisco IOS/IOS-XE routers, checking for stale LSAs
#   (age approaching MaxAge 3600s), LSA counts per area, and type-7 to type-5
#   redistribution. Complements ospf_neighbors.pl by validating database health
#   rather than adjacency state.
#
# Usage:
#   ospf_lsdb_audit.pl --host <ip> --user <user> --pass <pass> [--log <file>]
#   ospf_lsdb_audit.pl --file <device_list.txt> [--log <file>]
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH enabled on device; user needs at minimum 'show' privilege level
#
# Output:
#   Table of LSA counts, stale LSA warnings, and per-area summary to STDOUT.
#   Optionally mirrors to a log file with timestamps.

my ($host, $user, $pass, $device_file, $log_file);
my $timeout = 15;
my $stale_threshold = 3000;  # warn when LSA age exceeds this (seconds before MaxAge)

GetOptions(
    'host=s'   => \$host,
    'user=s'   => \$user,
    'pass=s'   => \$pass,
    'file=s'   => \$device_file,
    'log=s'    => \$log_file,
    'timeout=i' => \$timeout,
) or die "Usage: $0 --host <ip> --user <user> --pass <pass> [--log <file>]\n"
       . "       $0 --file <device_list.txt> [--log <file>]\n";

die "Provide --host or --file\n" unless $host || $device_file;
die "Provide --user and --pass when using --host\n"
    if $host && (!$user || !$pass);

my $LOG;
if ($log_file) {
    open($LOG, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
    $LOG->autoflush(1);
}

sub logprint {
    my ($msg) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    print "$msg\n";
    print $LOG "[$ts] $msg\n" if $LOG;
}

sub audit_device {
    my ($h, $u, $p) = @_;
    logprint("=" x 60);
    logprint("Host: $h");

    my $ssh = Net::SSH::Expect->new(
        host        => $h,
        user        => $u,
        password    => $p,
        raw_pty     => 1,
        timeout     => $timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    my $login;
    eval { $login = $ssh->login() };
    if ($@ || !defined $login || $login !~ /[>#]/) {
        logprint("  ERROR: SSH login failed - $@");
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('[>#]', 5);

    # Grab full LSDB summary
    $ssh->send("show ip ospf database\n");
    my $db_output = $ssh->waitfor('[>#]', 30) // '';

    # Grab detail for age checking (summary LSAs only to keep output bounded)
    $ssh->send("show ip ospf database summary\n");
    my $sum_output = $ssh->waitfor('[>#]', 30) // '';

    $ssh->send("exit\n");

    # Parse area/LSA type counts from database header
    my %areas;
    my $current_area = '';
    for my $line (split /\n/, $db_output) {
        if ($line =~ /OSPF Router\s+with\s+ID.+\((\d+\.\d+\.\d+\.\d+)\)/) {
            logprint("  Router ID: $1");
        }
        if ($line =~ /(?:Area|Router Link States in Area)\s+([\d.]+)/) {
            $current_area = $1;
            $areas{$current_area} //= { router => 0, network => 0, summary => 0, asbr => 0, external => 0, nssa => 0 };
        }
        next unless $current_area;
        $areas{$current_area}{router}++   if $line =~ /^\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+0x/ && $db_output =~ /Router Link/;
        $areas{$current_area}{network}++  if $line =~ /Net Link/;
        $areas{$current_area}{summary}++  if $line =~ /Sum Net/;
        $areas{$current_area}{external}++ if $line =~ /Type-5/;
        $areas{$current_area}{nssa}++     if $line =~ /Type-7/;
    }

    # Detect stale LSAs from age field in summary output
    my @stale;
    while ($sum_output =~ /(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+0x/g) {
        my ($lsid, $adv, $age) = ($1, $2, $3);
        if ($age >= $stale_threshold) {
            push @stale, sprintf("LSA %s (adv %s) age=%ss", $lsid, $adv, $age);
        }
    }

    # Report
    if (%areas) {
        logprint(sprintf("  %-18s %6s %7s %7s %8s %6s", "Area", "Router", "Network", "Summary", "External", "NSSA"));
        for my $area (sort keys %areas) {
            my $a = $areas{$area};
            logprint(sprintf("  %-18s %6d %7d %7d %8d %6d",
                $area, $a->{router}, $a->{network}, $a->{summary}, $a->{external}, $a->{nssa}));
        }
    } else {
        logprint("  WARNING: No OSPF areas found - OSPF may not be running");
    }

    if (@stale) {
        logprint("  STALE LSAs (age >= ${stale_threshold}s):");
        logprint("    $_") for @stale;
    } else {
        logprint("  No stale LSAs detected");
    }
}

my @devices;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        next unless /\S/;
        my ($h, $u, $p) = split /\s+/, $_, 3;
        push @devices, [$h, $u, $p] if $h && $u && $p;
    }
    close $fh;
} else {
    push @devices, [$host, $user, $pass];
}

logprint("OSPF LSDB Audit - " . strftime('%Y-%m-%d %H:%M:%S', localtime));
logprint("Stale threshold: ${stale_threshold}s (MaxAge=3600s)");
audit_device(@$_) for @devices;
logprint("Done.");

close $LOG if $LOG;