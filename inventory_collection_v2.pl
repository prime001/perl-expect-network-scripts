#!/usr/bin/perl
# =============================================================================
# cdp_lldp_discovery.pl - CDP/LLDP Neighbor Discovery and Topology Mapper
#
# Purpose : Collect CDP and LLDP neighbor tables from network devices to
#           document adjacencies, verify cabling, and build topology maps.
#           Useful for auditing undocumented links and onboarding new sites.
#
# Usage   : perl cdp_lldp_discovery.pl -h 10.0.0.1 -u admin -p secret
#           perl cdp_lldp_discovery.pl -f devices.txt -u admin -p secret -l out.log
#           perl cdp_lldp_discovery.pl -h 10.0.0.1 -u admin -p secret --lldp-only
#
# Options : -h host       Single device IP or hostname
#           -f file       File with one device per line (# = comment)
#           -u user       SSH username
#           -p pass       SSH password
#           -l logfile    Write output to file in addition to STDOUT
#           -t timeout    SSH timeout in seconds (default: 30)
#           --lldp-only   Skip CDP collection (non-Cisco or CDP disabled)
#
# Prereqs : cpan install Net::SSH::Expect Getopt::Long
#           SSH enabled; read-only privilege level sufficient
# Tested  : Cisco IOS 15.x, IOS-XE 16.x, NX-OS 9.x
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $logfile, $lldp_only, $timeout);
$timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$file,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'l|log=s'     => \$logfile,
    't|timeout=i' => \$timeout,
    'lldp-only'   => \$lldp_only,
) or die usage();

die usage() unless ($host || $file) && $user && $pass;

my @devices;
if ($file) {
    open(my $fh, '<', $file) or die "Cannot open '$file': $!\n";
    while (<$fh>) { chomp; next if /^\s*$/ || /^#/; push @devices, $_; }
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>', $logfile) or die "Cannot open log '$logfile': $!\n";
}

my $stamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
out("CDP/LLDP Neighbor Discovery Report  —  $stamp\n" . "=" x 68 . "\n");

for my $dev (@devices) {
    out("\n[*] Connecting to $dev ...\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host       => $dev,
            user       => $user,
            password   => $pass,
            raw_pty    => 1,
            timeout    => $timeout,
            ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
    };
    if ($@ || !$ssh) { out("[!] SSH init failed for $dev: $@\n"); next; }

    my $logged_in = eval { $ssh->login() };
    if ($@ || !$logged_in) { out("[!] Auth failed for $dev\n"); next; }

    $ssh->exec("terminal length 0");

    out("-" x 68 . "\nDevice: $dev\n" . "-" x 68 . "\n");

    unless ($lldp_only) {
        my $cdp = $ssh->exec("show cdp neighbors detail");
        out("\n--- CDP Neighbors ---\n");
        if ($cdp && $cdp !~ /CDP is not enabled|% Invalid/i) {
            print_neighbors(parse_cdp($cdp));
        } else {
            out("  CDP not enabled or no neighbors found\n");
        }
    }

    my $lldp = $ssh->exec("show lldp neighbors detail");
    out("\n--- LLDP Neighbors ---\n");
    if ($lldp && $lldp !~ /LLDP is not enabled|% Invalid/i) {
        print_neighbors(parse_lldp($lldp));
    } else {
        out("  LLDP not enabled or no neighbors found\n");
    }

    $ssh->close();
}

out("\n" . "=" x 68 . "\nDone. Scanned " . scalar(@devices) . " device(s).\n");
close($log_fh) if $log_fh;

# ---- Parsers ----------------------------------------------------------------

sub parse_cdp {
    my @rows; my %cur;
    for (split /\n/, $_[0]) {
        if (/^Device ID:\s*(.+)/)                    { push @rows, {%cur} if %cur; %cur = (id => $1); }
        elsif (/IP address:\s*(\S+)/i)               { $cur{ip}  ||= $1; }
        elsif (/Interface:\s*(\S+),.*Port ID.*?:\s*(\S+)/i) { @cur{qw(local remote)} = ($1,$2); }
        elsif (/Platform:\s*([^,]+)/)                { ($cur{plat} = $1) =~ s/\s+$//; }
    }
    push @rows, {%cur} if %cur;
    return @rows;
}

sub parse_lldp {
    my @rows; my %cur;
    for (split /\n/, $_[0]) {
        if (/System Name:\s*(.+)/)                   { push @rows, {%cur} if %cur; %cur = (id => $1); }
        elsif (/Management Addr.*?(\d+\.\d+\.\d+\.\d+)/i) { $cur{ip} ||= $1; }
        elsif (/Local Intf:\s*(\S+)/i)               { $cur{local}  = $1; }
        elsif (/Port id:\s*(\S+)/i)                  { $cur{remote} = $1; }
        elsif (/System Description:\s*(.+)/)         { ($cur{plat} = $1) =~ s/\s+$//; }
    }
    push @rows, {%cur} if %cur;
    return @rows;
}

sub print_neighbors {
    my @rows = @_;
    unless (@rows) { out("  No neighbors found\n"); return; }
    out(sprintf("  %-32s %-16s %-20s %-18s\n", "Neighbor", "IP", "Local Port", "Remote Port"));
    out("  " . "-" x 88 . "\n");
    for my $n (@rows) {
        out(sprintf("  %-32s %-16s %-20s %-18s\n",
            substr($n->{id}     // 'N/A', 0, 31),
            substr($n->{ip}     // 'N/A', 0, 15),
            substr($n->{local}  // 'N/A', 0, 19),
            substr($n->{remote} // 'N/A', 0, 17),
        ));
    }
}

sub out {
    print $_[0];
    print $log_fh $_[0] if $log_fh;
}

sub usage { "Usage: $0 -h <host>|-f <file> -u <user> -p <pass> [-l log] [-t sec] [--lldp-only]\n" }