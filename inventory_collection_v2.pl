#!/usr/bin/perl
#
# arp_table.pl - Network ARP Table Collection
#
# PURPOSE:
#   Connects to Cisco IOS/IOS-XE/NX-OS devices via SSH and collects ARP table
#   entries. Generates IP-to-MAC mapping reports useful for endpoint tracking,
#   duplicate IP detection, and network forensics.
#
# USAGE:
#   Single device:   ./arp_table.pl -h 192.168.1.1 -u admin -p secret
#   Device list:     ./arp_table.pl -f hosts.txt -u admin -p secret
#   With CSV output: ./arp_table.pl -f hosts.txt -u admin -p secret -o arp_report.csv
#   Custom timeout:  ./arp_table.pl -h 10.0.0.1 -u admin -p secret -t 30
#
# HOST FILE FORMAT:
#   One IP or hostname per line. Lines beginning with # are skipped.
#
# PREREQUISITES:
#   cpan Net::SSH::Expect Getopt::Long
#
# SUPPORTED PLATFORMS:
#   Cisco IOS, IOS-XE, NX-OS (show ip arp)

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($host, $user, $pass, $hosts_file, $output_file);
my $timeout = 20;

GetOptions(
    'h|host=s'    => \$host,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'f|file=s'    => \$hosts_file,
    'o|output=s'  => \$output_file,
    't|timeout=i' => \$timeout,
) or die usage();

die usage() unless $user && $pass && ($host || $hosts_file);

sub usage {
    return "Usage: $0 -h HOST | -f FILE -u USER -p PASS [-o OUTPUT.csv] [-t SECS]\n";
}

my @devices;
if ($hosts_file) {
    open my $fh, '<', $hosts_file or die "Cannot open $hosts_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^\s*#/;
        push @devices, $_;
    }
    close $fh;
} else {
    @devices = ($host);
}

my $logfh;
if ($output_file) {
    open $logfh, '>', $output_file or die "Cannot open $output_file: $!\n";
    print $logfh "timestamp,device,ip_address,mac_address,age_min,interface\n";
}

my $run_ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
print "ARP Table Collection  $run_ts\n";
printf "%-20s %-18s %-17s %-8s %s\n", 'Device', 'IP Address', 'MAC Address', 'Age', 'Interface';
print '-' x 78 . "\n";

my $total = 0;

for my $device (@devices) {
    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $user,
        password => $pass,
        raw_pty  => 1,
        timeout  => $timeout,
    );

    my $prompt = eval { $ssh->login() };
    if ($@ || !defined $prompt) {
        warn "SKIP $device: authentication failed\n";
        next;
    }

    $ssh->exec("terminal length 0");

    my $raw = eval { $ssh->exec("show ip arp") };
    if ($@ || !defined $raw || $raw eq '') {
        warn "SKIP $device: no output received\n";
        $ssh->close();
        next;
    }

    my $count = 0;
    for my $line (split /\n/, $raw) {
        # Cisco format: Internet  10.0.0.1   5   001a.2b3c.4d5e  ARPA  Gi0/1
        next unless $line =~ /^Internet\s+
            (\d+\.\d+\.\d+\.\d+)\s+
            (\d+|-)\s+
            ([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+
            \S+\s+(\S+)/xi;

        my ($ip, $age, $mac, $intf) = ($1, $2, $3, $4);
        printf "%-20s %-18s %-17s %-8s %s\n", $device, $ip, $mac, $age, $intf;
        print $logfh "$run_ts,$device,$ip,$mac,$age,$intf\n" if $logfh;
        $count++;
    }

    printf "  [%s: %d entries]\n", $device, $count;
    $total += $count;
    $ssh->close();
}

print '-' x 78 . "\n";
printf "Total: %d ARP entries across %d device(s)\n", $total, scalar @devices;

if ($logfh) {
    close $logfh;
    print "CSV saved to $output_file\n";
}