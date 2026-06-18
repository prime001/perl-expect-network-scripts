#!/usr/bin/perl
# =============================================================================
# arp_audit.pl - ARP Table Collector and Duplicate IP/MAC Detector
# =============================================================================
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and collects the ARP table.
#   Flags duplicate IP addresses and MAC addresses that may indicate IP
#   conflicts, ARP spoofing, or misconfigured devices on the network.
#
# Usage:
#   Single device:  ./arp_audit.pl -h 192.168.1.1 -u admin -p password
#   Device file:    ./arp_audit.pl -f devices.txt -u admin -p password
#   With log file:  ./arp_audit.pl -h 192.168.1.1 -u admin -p password -l audit.log
#
# Prerequisites:
#   - Perl modules: Net::SSH::Expect, Getopt::Long
#   - Install: cpan Net::SSH::Expect
#   - SSH access with privilege exec level on target devices
#
# Device file format (one IP/hostname per line; lines starting with # ignored):
#   10.0.0.1
#   10.0.0.2   # core-sw-01
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file);
my $timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|password=s' => \$password,
    'l|log=s'      => \$log_file,
    't|timeout=i'  => \$timeout,
) or die usage();

die usage() unless ($host || $device_file) && $username && $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open device file '$device_file': $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/\s+$//;
        push @devices, $_ if $_;
    }
    close $fh;
}

die "No devices to process.\n" unless @devices;

my $log_fh;
if ($log_file) {
    open($log_fh, '>', $log_file) or die "Cannot open log file '$log_file': $!\n";
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
out("=" x 62);
out("ARP Audit Report - $ts");
out("=" x 62);

for my $device (@devices) {
    audit_device($device);
}

close $log_fh if $log_fh;

sub audit_device {
    my ($device) = @_;
    out("\n[*] Connecting to $device ...");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host       => $device,
            user       => $username,
            password   => $password,
            ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
            timeout    => $timeout,
            raw_pty    => 1,
        );
        $ssh->login();
    };
    if ($@) {
        out("[ERROR] $device: connection failed - $@");
        return;
    }

    eval { $ssh->send("terminal length 0\n"); $ssh->waitfor('\S+[#>]', 5); };

    my $arp_output = '';
    eval {
        $ssh->send("show ip arp\n");
        $arp_output = $ssh->waitfor('\S+[#>]', $timeout);
    };
    if ($@) {
        out("[ERROR] $device: failed to run 'show ip arp' - $@");
        $ssh->close();
        return;
    }

    eval { $ssh->send("exit\n"); $ssh->close(); };

    parse_arp($device, $arp_output);
}

sub parse_arp {
    my ($device, $output) = @_;

    my (%ip_to_macs, %mac_to_ips, @entries);

    for my $line (split /\n/, $output) {
        next unless $line =~ /^Internet\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\S+\s+(\S+)/;
        my ($ip, $age, $mac, $iface) = ($1, $2, lc($3), $4);
        push @entries, { ip => $ip, age => $age, mac => $mac, iface => $iface };
        push @{ $ip_to_macs{$ip}  }, $mac;
        push @{ $mac_to_ips{$mac} }, $ip;
    }

    out(sprintf("[%s] %d ARP entries collected.", $device, scalar @entries));

    my @dup_ips  = sort grep { @{ $ip_to_macs{$_} } > 1 } keys %ip_to_macs;
    my @dup_macs = sort grep { @{ $mac_to_ips{$_} } > 1 } keys %mac_to_ips;

    if (@dup_ips) {
        out("[WARN] Duplicate IPs (IP conflict or ARP spoofing):");
        out(sprintf("  %-18s -> %s", $_, join(", ", @{ $ip_to_macs{$_} }))) for @dup_ips;
    }
    if (@dup_macs) {
        out("[WARN] Duplicate MACs (multi-IP host or MAC spoofing):");
        out(sprintf("  %-20s -> %s", $_, join(", ", @{ $mac_to_ips{$_} }))) for @dup_macs;
    }
    unless (@dup_ips || @dup_macs) {
        out("[OK]   No duplicate IPs or MACs detected.");
    }

    out(sprintf("\n  %-18s %-5s %-20s %s", "IP Address", "Age", "MAC Address", "Interface"));
    out("  " . "-" x 58);
    for my $e (sort { $a->{ip} cmp $b->{ip} } @entries) {
        out(sprintf("  %-18s %-5s %-20s %s", $e->{ip}, $e->{age}, $e->{mac}, $e->{iface}));
    }
}

sub out {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}

sub usage {
    return <<'END';
Usage:
  arp_audit.pl -h <host>   -u <user> -p <pass> [-l <logfile>] [-t <secs>]
  arp_audit.pl -f <file>   -u <user> -p <pass> [-l <logfile>] [-t <secs>]

Options:
  -h, --host      Single device IP or hostname
  -f, --file      File with list of devices (one per line)
  -u, --user      SSH username
  -p, --password  SSH password
  -l, --log       Optional output log file
  -t, --timeout   SSH timeout in seconds (default: 30)
END
}