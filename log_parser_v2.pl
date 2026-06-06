#!/usr/bin/perl
# cdp_neighbors.pl - CDP/LLDP Neighbor Discovery via SSH
#
# Purpose:
#   Connects to Cisco network devices via SSH and collects CDP and LLDP
#   neighbor tables. Useful for building L2 topology maps, auditing cabling,
#   and verifying that adjacencies match your network diagram.
#
# Usage:
#   ./cdp_neighbors.pl -h <host>        (single device)
#   ./cdp_neighbors.pl -f <device_file> (one host per line, # comments ok)
#   Options: -u <username>  -p <password>  -l <logfile>
#   Credentials also read from NET_USER / NET_PASS environment variables.
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   Devices must have 'show cdp neighbors detail' and/or 'show lldp neighbors detail'
#   available at the privilege level used to log in.

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $logfile);
my $username = $ENV{NET_USER} // 'admin';
my $password = $ENV{NET_PASS} // '';

GetOptions(
    'h|host=s' => \$host,
    'f|file=s' => \$device_file,
    'u|user=s' => \$username,
    'p|pass=s' => \$password,
    'l|log=s'  => \$logfile,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile]\n";

die "Specify -h <host> or -f <file>\n" unless $host || $device_file;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if $_; }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub parse_cdp {
    my ($output) = @_;
    my (@neighbors, %cur);
    for my $line (split /\n/, $output) {
        if ($line =~ /^Device ID:\s*(.+)/) {
            push @neighbors, {%cur} if %cur;
            %cur = (device_id => $1);
        } elsif ($line =~ /IP(?:v4)? address:\s*(\S+)/i)   { $cur{ip}         //= $1 }
        elsif ($line =~ /Interface:\s*(\S+),\s*Port ID.*?:\s*(\S+)/i) {
            $cur{local_intf} = $1; $cur{remote_intf} = $2;
        }
        elsif ($line =~ /Platform:\s*([^,]+)/i)             { ($cur{platform} = $1) =~ s/^\s+|\s+$//g }
    }
    push @neighbors, {%cur} if %cur;

    if (@neighbors) {
        out(sprintf("  %-32s %-20s %-18s %-16s %s\n", "CDP Neighbor","Platform","Local Intf","Remote Intf","Mgmt IP"));
        out("  " . "-" x 102 . "\n");
        for my $n (@neighbors) {
            out(sprintf("  %-32s %-20s %-18s %-16s %s\n",
                $n->{device_id}   // '?',
                substr($n->{platform} // '?', 0, 18),
                $n->{local_intf}  // '?',
                $n->{remote_intf} // '?',
                $n->{ip}          // 'n/a'));
        }
        out("  CDP neighbors: " . scalar(@neighbors) . "\n");
    } else {
        out("  No CDP neighbors found\n");
    }
}

sub parse_lldp {
    my ($output) = @_;
    my (@neighbors, %cur);
    for my $line (split /\n/, $output) {
        if ($line =~ /^Local Intf:\s*(\S+)/i) {
            push @neighbors, {%cur} if %cur && $cur{local_intf};
            %cur = (local_intf => $1);
        } elsif ($line =~ /System Name:\s*(.+)/i)  { ($cur{name} = $1) =~ s/^\s+|\s+$//g }
        elsif ($line =~ /Port id:\s*(\S+)/i)        { $cur{remote_intf} = $1 }
        elsif ($line =~ /(\d+\.\d+\.\d+\.\d+)/)    { $cur{ip} //= $1 }
    }
    push @neighbors, {%cur} if %cur && $cur{local_intf};

    if (@neighbors) {
        out(sprintf("  %-32s %-18s %-16s %s\n", "LLDP Neighbor","Local Intf","Remote Intf","Mgmt IP"));
        out("  " . "-" x 82 . "\n");
        for my $n (@neighbors) {
            out(sprintf("  %-32s %-18s %-16s %s\n",
                $n->{name}        // '?',
                $n->{local_intf}  // '?',
                $n->{remote_intf} // '?',
                $n->{ip}          // 'n/a'));
        }
        out("  LLDP neighbors: " . scalar(@neighbors) . "\n");
    } else {
        out("  No LLDP neighbors found\n");
    }
}

sub audit_device {
    my ($device) = @_;
    out("=" x 64 . "\n");
    out("Device: $device  [" . strftime('%Y-%m-%d %H:%M:%S', localtime) . "]\n");
    out("=" x 64 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $username,
        password => $password,
        raw_pty  => 1,
        timeout  => 15,
    );

    eval { $ssh->login() };
    if ($@) {
        out("  ERROR: login failed: $@\n\n");
        return;
    }

    $ssh->exec("terminal length 0");

    my $cdp = $ssh->exec("show cdp neighbors detail");
    if (!defined $cdp || $cdp =~ /not enabled|Invalid input/i) {
        out("  CDP: not enabled or not supported on this device\n");
    } else {
        parse_cdp($cdp);
    }

    my $lldp = $ssh->exec("show lldp neighbors detail");
    if (!defined $lldp || $lldp =~ /not enabled|Invalid input/i) {
        out("  LLDP: not enabled or not supported on this device\n");
    } else {
        parse_lldp($lldp);
    }

    $ssh->close();
    out("\n");
}

audit_device($_) for @devices;
close $log_fh if $log_fh;