#!/usr/bin/perl
# =============================================================================
# ospf_lsdb_check.pl - OSPF Link-State Database Analyzer
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and analyzes the OSPF
#   link-state database (LSDB). Counts LSAs by type per area, flags databases
#   with excessive external LSA counts (potential redistribution leak), and
#   reports area type anomalies. Complements ospf_neighbors.pl (neighbor state)
#   by validating the database content itself.
#
# Usage:
#   Single device:  ./ospf_lsdb_check.pl -h 10.0.0.1
#   Fleet sweep:    ./ospf_lsdb_check.pl -f routers.txt -l lsdb_audit.log
#   Custom process: ./ospf_lsdb_check.pl -h 10.0.0.1 -P 100
#   Custom creds:   ./ospf_lsdb_check.pl -h 10.0.0.1 -u netops -p secretpass
#   Set ext limit:  ./ospf_lsdb_check.pl -f routers.txt --max-ext 500
#
# Device file format: one IP/hostname per line, # for comments
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH read-only access to Cisco IOS/IOS-XE (privilege 1+)
#   OSPF must be running on the device
#
# Exit codes:
#   0 - All databases healthy
#   1 - Anomaly detected (LSA threshold exceeded or area mismatch)
#   2 - All connection attempts failed
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $log_file, $username, $password);
my ($timeout, $process_id, $max_ext, $help);
$username   = $ENV{NET_USER} // 'admin';
$password   = $ENV{NET_PASS} // '';
$timeout    = 20;
$process_id = 1;
$max_ext    = 1000;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$device_file,
    'l|log=s'     => \$log_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    't|timeout=i' => \$timeout,
    'P|process=i' => \$process_id,
    'max-ext=i'   => \$max_ext,
    'help'        => \$help,
) or die "Error parsing options. Use --help for usage.\n";

if ($help) {
    system("grep '^#' $0 | sed 's/^# \\?//'");
    exit 0;
}
die "Specify -h <host> or -f <file>\n" unless $host || $device_file;

unless ($password) {
    print "Password for $username: ";
    system('stty -echo');
    chomp($password = <STDIN>);
    system('stty echo');
    print "\n";
}

my @devices;
push @devices, $host if $host;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*[#\s]/; push @devices, $_; }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open $log_file: $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts      = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $anomaly = 0;
my $failed  = 0;

out("=" x 70 . "\n");
out("OSPF LSDB Audit  |  $ts  |  Ext-LSA limit: $max_ext\n");
out("=" x 70 . "\n");

for my $device (@devices) {
    out("\n[ $device ]\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $username,
        password => $password,
        raw_pty  => 1,
        timeout  => $timeout,
    );

    my $login;
    eval { $login = $ssh->login() };
    if ($@ || !defined $login) {
        out("  ERROR: Login failed - " . ($@ // 'unknown') . "\n");
        $failed++;
        next;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('\$|#|>', 5);

    $ssh->send("show ip ospf $process_id");
    my $proc = $ssh->waitfor('\$|#|>', $timeout) // '';

    my $router_id = ($proc =~ /Router ID (\d+\.\d+\.\d+\.\d+)/) ? $1 : 'unknown';
    my %area_types;
    while ($proc =~ /Area\s+(\S+).*?(?:\((\w[\w\s]+?)\))?(?:\s*$)/mg) {
        $area_types{$1} = lc($2 // 'normal');
    }
    out("  Router ID: $router_id\n");

    $ssh->send("show ip ospf $process_id database summary");
    my $db_sum = $ssh->waitfor('\$|#|>', $timeout) // '';

    my %lsa_counts;
    my $cur_area = '0.0.0.0';

    for my $line (split /\n/, $db_sum) {
        $cur_area = $1 if $line =~ /Area\s+(\S+)\s+database/i;
        if ($line =~ /Number of (\w[\w\s]+?)\s+LSA[s]?\s+(\d+)/i) {
            $lsa_counts{$cur_area}{lc($1)} += $2;
        }
    }

    if (!%lsa_counts) {
        $ssh->send("show ip ospf $process_id database");
        my $db = $ssh->waitfor('\$|#|>', $timeout) // '';
        $cur_area = '0.0.0.0';
        for my $line (split /\n/, $db) {
            $cur_area = $1 if $line =~ /OSPF Router with ID.*?Area\s+\((\S+)\)/i;
            if ($line =~ /^\s+(Router|Network|Summary Net|Summary ASB|Type-5 AS External|NSSA External)\s+Link/i) {
                $lsa_counts{$cur_area}{lc($1)}++;
            }
        }
    }

    if (!%lsa_counts) {
        out("  WARN: No LSDB data retrieved (OSPF down or process ID mismatch?)\n");
        $anomaly++;
        $ssh->close();
        next;
    }

    for my $area (sort keys %lsa_counts) {
        my $atype = $area_types{$area} // 'normal';
        out(sprintf("  Area %-18s [%s]\n", $area, $atype));
        for my $type (sort keys %{ $lsa_counts{$area} }) {
            my $count = $lsa_counts{$area}{$type};
            my $flag  = '';
            if ($type =~ /external|type.5/i) {
                if ($count > $max_ext) {
                    $flag = " !! EXCEEDS LIMIT ($max_ext)";
                    $anomaly++;
                }
                if ($atype =~ /stub/) {
                    $flag .= " !! EXT LSAS IN STUB AREA";
                    $anomaly++;
                }
            }
            out(sprintf("    %-30s %5d%s\n", $type, $count, $flag));
        }
    }

    $ssh->close();
}

out("\n" . "=" x 70 . "\n");
out(sprintf("Devices: %d  |  Failed: %d  |  Anomalies flagged: %d\n",
    scalar(@devices), $failed, $anomaly));
out("=" x 70 . "\n");

close $log_fh if $log_fh;

exit(($failed == scalar(@devices)) ? 2 : ($anomaly ? 1 : 0));