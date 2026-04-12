#!/usr/bin/perl
#
# cdp_lldp_neighbors.pl - Network Topology Discovery via CDP/LLDP
#
# Purpose:
#   Collects CDP and LLDP neighbor information from Cisco IOS/NX-OS devices
#   to aid in network topology mapping and documentation. Parses neighbor
#   details including device ID, local/remote interface, platform, and
#   IP address for each discovered neighbor.
#
# Usage:
#   Single device:  ./cdp_lldp_neighbors.pl -h 192.168.1.1 [-u admin] [-p password] [-l logfile]
#   Device file:    ./cdp_lldp_neighbors.pl -f devices.txt [-u admin] [-p password] [-l logfile]
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   Devices must have 'cdp run' and/or 'lldp run' configured
#   SSH must be enabled on target devices
#
# Output:
#   Tabular neighbor summary per device, optionally written to log file
#
# Author: Network Engineering
# Version: 1.0

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);

our %opts;
getopts('h:f:u:p:l:', \%opts);

my $username = $opts{u} || $ENV{NET_USER} || 'admin';
my $password = $opts{p} || $ENV{NET_PASS} || die "Password required: use -p or set NET_PASS\n";
my $logfile  = $opts{l};
my @devices;

if ($opts{h}) {
    push @devices, $opts{h};
} elsif ($opts{f}) {
    open(my $fh, '<', $opts{f}) or die "Cannot open device file '$opts{f}': $!\n";
    while (<$fh>) {
        chomp;
        s/#.*//;
        s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
} else {
    die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile]\n";
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log file '$logfile': $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
output("=" x 70);
output("CDP/LLDP Neighbor Discovery  --  $timestamp");
output("=" x 70);

for my $device (@devices) {
    output("\n>>> Device: $device");
    output("-" x 50);

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $username,
        password     => $password,
        raw_pty     => 1,
        timeout     => 15,
    );

    eval {
        my $login = $ssh->login();
        unless ($login =~ /[>#]/) {
            die "Authentication failed or unexpected prompt\n";
        }

        $ssh->send("terminal length 0");
        $ssh->waitfor('[>#]', 5);

        # Try CDP first
        $ssh->send("show cdp neighbors detail");
        my $cdp_out = $ssh->waitfor('[>#]', 30);

        if ($cdp_out && $cdp_out !~ /CDP is not enabled|Invalid input/) {
            output("  [CDP Neighbors]");
            parse_cdp($cdp_out);
        }

        # Try LLDP
        $ssh->send("show lldp neighbors detail");
        my $lldp_out = $ssh->waitfor('[>#]', 30);

        if ($lldp_out && $lldp_out !~ /LLDP is not enabled|Invalid input/) {
            output("  [LLDP Neighbors]");
            parse_lldp($lldp_out);
        }

        $ssh->send("exit");
        $ssh->close();
    };
    if ($@) {
        my $err = $@;
        $err =~ s/\n.*//s;
        output("  ERROR: $err");
    }
}

output("\nDone.");
close $log_fh if $log_fh;

sub parse_cdp {
    my ($output) = @_;
    my ($device_id, $local_intf, $remote_intf, $platform, $ip);
    my $found = 0;

    for my $line (split /\n/, $output) {
        if ($line =~ /^Device ID:\s*(.+)/)          { $device_id   = $1; $found = 1; }
        if ($line =~ /Interface:\s*([\w\/\.]+)/i)    { $local_intf  = $1; }
        if ($line =~ /Port ID.*?:\s*([\w\/\.]+)/i)   { $remote_intf = $1; }
        if ($line =~ /Platform:\s*([^,]+)/)          { $platform    = $1; }
        if ($line =~ /IP address:\s*([\d\.]+)/i)     { $ip          = $1; }

        if ($line =~ /^-{3,}/ && $found) {
            output(sprintf("    %-30s %-18s %-18s %-20s %s",
                $device_id // 'unknown',
                $local_intf // '-',
                $remote_intf // '-',
                $platform // '-',
                $ip // '-'));
            ($device_id, $local_intf, $remote_intf, $platform, $ip) = (undef) x 5;
            $found = 0;
        }
    }
    if ($found && $device_id) {
        output(sprintf("    %-30s %-18s %-18s %-20s %s",
            $device_id, $local_intf // '-', $remote_intf // '-',
            $platform // '-', $ip // '-'));
    }
}

sub parse_lldp {
    my ($output) = @_;
    my ($sys_name, $local_intf, $remote_intf, $sys_desc, $mgmt_ip);
    my $found = 0;

    for my $line (split /\n/, $output) {
        if ($line =~ /^Local Intf:\s*([\w\/\.]+)/i)       { $local_intf  = $1; $found = 1; }
        if ($line =~ /System Name:\s*(.+)/i)               { $sys_name    = $1; }
        if ($line =~ /Port id:\s*([\w\/\.]+)/i)            { $remote_intf = $1; }
        if ($line =~ /System Description:\s*(.+)/i)        { $sys_desc    = $1; }
        if ($line =~ /Management Addresses.*?([\d\.]+)/i)  { $mgmt_ip     = $1; }

        if ($line =~ /^-{3,}/ && $found) {
            output(sprintf("    %-30s %-18s %-18s %-20s %s",
                $sys_name // 'unknown',
                $local_intf // '-',
                $remote_intf // '-',
                $sys_desc // '-',
                $mgmt_ip // '-'));
            ($sys_name, $local_intf, $remote_intf, $sys_desc, $mgmt_ip) = (undef) x 5;
            $found = 0;
        }
    }
}

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}