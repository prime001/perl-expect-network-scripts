#!/usr/bin/perl
#
# cdp_lldp_topology.pl - CDP/LLDP Neighbor Discovery and Topology Mapper
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and collects CDP and LLDP
#   neighbor information to build a network topology map. Useful for validating
#   physical cabling, discovering undocumented neighbors, and auditing
#   neighbor relationships across the network.
#
# Usage:
#   Single device:  perl cdp_lldp_topology.pl -h 192.168.1.1
#   Device file:    perl cdp_lldp_topology.pl -f devices.txt
#   With logging:   perl cdp_lldp_topology.pl -f devices.txt -l topology.log
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH key-based auth or password in environment: NET_PASS / NET_USER
#   CDP and/or LLDP enabled on target devices
#
# Author: Network Engineering
# Version: 1.0

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $device_file, $log_file, $help);
my $username = $ENV{NET_USER} // 'admin';
my $password = $ENV{NET_PASS} // die "ERROR: Set NET_PASS environment variable\n";
my $timeout  = 30;

GetOptions(
    'h|host=s'    => \$host_arg,
    'f|file=s'    => \$device_file,
    'l|log=s'     => \$log_file,
    'help'        => \$help,
) or usage();

usage() if $help or (!$host_arg and !$device_file);

my @devices;
if ($host_arg) {
    push @devices, $host_arg;
}
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open device file '$device_file': $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ or /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>', $log_file) or die "Cannot open log file '$log_file': $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
output("=" x 70);
output("CDP/LLDP Topology Discovery  |  $timestamp");
output("=" x 70);

for my $device (@devices) {
    output("\n[ Device: $device ]");
    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $device,
            user        => $username,
            password    => $password,
            raw_pty     => 1,
            timeout     => $timeout,
            ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
    };
    if ($@) {
        output("  ERROR: Failed to create SSH session - $@");
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ or !defined $login) {
        output("  ERROR: Authentication failed or connection refused");
        next;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$', 3);

    collect_cdp($ssh, $device);
    collect_lldp($ssh, $device);

    $ssh->send("exit");
    $ssh->close();
}

output("\n" . "=" x 70);
output("Discovery complete.");
close $log_fh if $log_fh;

sub collect_cdp {
    my ($ssh, $device) = @_;
    $ssh->send("show cdp neighbors detail");
    my $output = $ssh->waitfor('(#|\$)\s*$', $timeout);
    unless (defined $output) {
        output("  CDP: No response or not supported");
        return;
    }

    my @neighbors;
    my %entry;
    for my $line (split /\n/, $output) {
        if ($line =~ /^Device ID:\s*(.+)/)        { $entry{device_id}   = $1 }
        elsif ($line =~ /IP(?:v4)? address:\s*(\S+)/) { $entry{ip}       //= $1 }
        elsif ($line =~ /Platform:\s*([^,]+)/)    { $entry{platform}    = $1 }
        elsif ($line =~ /Interface:\s*(\S+),\s*Port ID.*?:\s*(\S+)/) {
            $entry{local_intf}  = $1;
            $entry{remote_intf} = $2;
        }
        elsif ($line =~ /^-{5,}/ and %entry) {
            push @neighbors, {%entry};
            %entry = ();
        }
    }
    push @neighbors, {%entry} if %entry and $entry{device_id};

    if (@neighbors) {
        output(sprintf("  %-30s %-16s %-20s %-20s %-20s",
            "CDP", "Neighbor IP", "Local Intf", "Remote Intf", "Platform"));
        output("  " . "-" x 90);
        for my $n (@neighbors) {
            output(sprintf("  %-30s %-16s %-20s %-20s %-20s",
                $n->{device_id}   // 'unknown',
                $n->{ip}          // 'N/A',
                $n->{local_intf}  // 'N/A',
                $n->{remote_intf} // 'N/A',
                $n->{platform}    // 'N/A'));
        }
    } else {
        output("  CDP: No neighbors found");
    }
}

sub collect_lldp {
    my ($ssh, $device) = @_;
    $ssh->send("show lldp neighbors detail");
    my $output = $ssh->waitfor('(#|\$)\s*$', $timeout);
    unless (defined $output) {
        output("  LLDP: No response");
        return;
    }

    return if $output =~ /LLDP.*not.*enabled|Invalid input/i;

    my @neighbors;
    my %entry;
    for my $line (split /\n/, $output) {
        if ($line =~ /^Local Intf:\s*(\S+)/)         { $entry{local_intf}   = $1 }
        elsif ($line =~ /System Name:\s*(.+)/)        { $entry{device_id}    = $1 }
        elsif ($line =~ /Management Addresses.*?(\d+\.\d+\.\d+\.\d+)/) {
            $entry{ip} //= $1;
        }
        elsif ($line =~ /Port id:\s*(\S+)/)           { $entry{remote_intf}  = $1 }
        elsif ($line =~ /System Description:\s*(.+)/) { $entry{platform}     = $1 }
        elsif ($line =~ /^-{5,}/ and %entry) {
            push @neighbors, {%entry};
            %entry = ();
        }
    }
    push @neighbors, {%entry} if %entry and $entry{device_id};

    if (@neighbors) {
        output(sprintf("  %-30s %-16s %-20s %-20s",
            "LLDP Neighbor", "Mgmt IP", "Local Intf", "Remote Port"));
        output("  " . "-" x 90);
        for my $n (@neighbors) {
            output(sprintf("  %-30s %-16s %-20s %-20s",
                $n->{device_id}   // 'unknown',
                $n->{ip}          // 'N/A',
                $n->{local_intf}  // 'N/A',
                $n->{remote_intf} // 'N/A'));
        }
    }
}

sub output {
    my ($line) = @_;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}

sub usage {
    print <<END;
Usage: $0 -h <host> | -f <device_file> [-l <logfile>]

  -h, --host    Single device IP or hostname
  -f, --file    File containing device IPs (one per line, # for comments)
  -l, --log     Optional output log file

Environment:
  NET_USER      SSH username (default: admin)
  NET_PASS      SSH password (required)
END
    exit 1;
}