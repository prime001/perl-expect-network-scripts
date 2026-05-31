#!/usr/bin/perl
#
# cdp_lldp_neighbors.pl - CDP/LLDP Neighbor Discovery and Topology Mapper
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and collects CDP and LLDP
#   neighbor adjacencies. Use this to document physical topology, validate
#   cabling after maintenance, or discover unexpected devices on the network.
#   Distinct from inventory_collection (hardware/SW info) -- this maps
#   port-to-port links between devices.
#
# Usage:
#   ./cdp_lldp_neighbors.pl -h 10.0.0.1 -u admin -p secret [-l neighbors.log]
#   ./cdp_lldp_neighbors.pl -f hosts.txt  -u admin -p secret [-l neighbors.log]
#
#   hosts.txt: one IP or hostname per line, # for comments
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#   SSH access to devices (port 22), CDP and/or LLDP enabled
#
# Output:
#   Per-device table of local port -> remote device/port/platform adjacencies
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $hosts_file, $username, $password, $logfile);
my $timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$hosts_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'l|log=s'     => \$logfile,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h <host>|-f <file> -u <user> -p <pass> [-l <logfile>] [-t <secs>]\n";

die "Provide -h <host> or -f <file>\n"  unless $host || $hosts_file;
die "Username required (-u)\n"          unless $username;
die "Password required (-p)\n"          unless $password;

my @targets;
if ($hosts_file) {
    open(my $fh, '<', $hosts_file) or die "Cannot open $hosts_file: $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        push @targets, $_ if length $_;
    }
    close $fh;
} else {
    push @targets, $host;
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log $logfile: $!\n";
}

sub emit {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub parse_cdp {
    my ($output) = @_;
    return unless $output && $output !~ /not enabled|invalid input/i;

    emit(sprintf("\n  %-24s %-32s %-22s %s\n",
        "Local Port", "Remote Device", "Remote Port", "Platform"));
    emit("  " . "-" x 86 . "\n");

    my ($lport, $rdev, $rport, $plat);
    for my $line (split /\n/, $output) {
        if    ($line =~ /^Device ID:\s*(\S+)/)                         { $rdev  = $1 }
        elsif ($line =~ /Interface:\s*(\S+),\s*Port ID[^:]*:\s*(\S+)/) { $lport = $1; $rport = $2 }
        elsif ($line =~ /Platform:\s*([^,]+)/)                         { ($plat = $1) =~ s/\s+$// }

        if ($lport && $rdev && $rport) {
            emit(sprintf("  %-24s %-32s %-22s %s\n",
                $lport, $rdev, $rport, $plat // 'unknown'));
            ($lport, $rdev, $rport, $plat) = (undef) x 4;
        }
    }
}

sub parse_lldp {
    my ($output) = @_;
    return unless $output && $output !~ /not enabled|invalid input|LLDP is not/i;

    emit(sprintf("\n  %-24s %-32s %s\n", "Local Port", "Remote System", "Remote Port"));
    emit("  " . "-" x 78 . "\n");

    my ($lport, $rsys, $rport);
    for my $line (split /\n/, $output) {
        if    ($line =~ /Local Intf:\s*(\S+)/)  { $lport = $1 }
        elsif ($line =~ /System Name:\s*(.+)/)  { ($rsys  = $1) =~ s/\s+$// }
        elsif ($line =~ /Port id:\s*(.+)/)       { ($rport = $1) =~ s/\s+$// }

        if ($lport && $rsys && $rport) {
            emit(sprintf("  %-24s %-32s %s\n", $lport, $rsys, $rport));
            ($lport, $rsys, $rport) = (undef) x 3;
        }
    }
}

sub collect_neighbors {
    my ($target) = @_;

    my $ssh = Net::SSH::Expect->new(
        host       => $target,
        user       => $username,
        password   => $password,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=15',
        timeout    => $timeout,
        raw_pty    => 1,
    );

    eval { $ssh->login() };
    if ($@) {
        emit("ERROR [$target]: SSH login failed -- $@\n");
        return;
    }

    $ssh->exec("terminal length 0");

    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    emit("\n" . "=" x 90 . "\n");
    emit("Device: $target    Collected: $ts\n");
    emit("=" x 90 . "\n");

    my $cdp = $ssh->exec("show cdp neighbors detail");
    if ($cdp && $cdp =~ /Device ID/i) {
        emit("CDP Neighbors:\n");
        parse_cdp($cdp);
    } else {
        emit("CDP: not available or no neighbors\n");
    }

    my $lldp = $ssh->exec("show lldp neighbors detail");
    if ($lldp && $lldp =~ /Local Intf/i) {
        emit("\nLLDP Neighbors:\n");
        parse_lldp($lldp);
    } else {
        emit("LLDP: not available or no neighbors\n");
    }

    $ssh->close();
}

my $start = strftime("%Y-%m-%d %H:%M:%S", localtime);
emit("CDP/LLDP Neighbor Discovery  |  $start  |  Targets: " . scalar(@targets) . "\n");

for my $target (@targets) {
    collect_neighbors($target);
}

emit("\n" . "=" x 90 . "\n");
emit("Scan complete: " . strftime("%Y-%m-%d %H:%M:%S", localtime) . "\n");

close $log_fh if $log_fh;
exit 0;