#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# arp_table.pl - Network Device ARP Table Collector
# =============================================================================
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE devices via SSH and collects
#   ARP table entries. Useful for IP-to-MAC tracking, detecting duplicate
#   IPs, and identifying unknown devices on network segments.
#
# Usage:
#   Single device:   ./arp_table.pl --host 192.168.1.1 --user admin
#   Device file:     ./arp_table.pl --file devices.txt --user admin --log arp_out.txt
#   With password:   ./arp_table.pl --host 10.0.0.1 --user admin --pass secretpass
#
# Device file format (one IP or hostname per line, # for comments):
#   192.168.1.1
#   192.168.1.2
#   # core-sw3 is down for maintenance
#   192.168.1.4
#
# Prerequisites:
#   - Perl modules: Net::SSH::Expect, Getopt::Long
#   - SSH access to devices with 'show ip arp' privilege
#   - Install: cpan Net::SSH::Expect
#
# Output columns: Device | IP Address | MAC Address | Age | Interface
# =============================================================================

my ($host, $file, $user, $pass, $logfile, $timeout, $help);
$timeout = 15;

GetOptions(
    'host=s'    => \$host,
    'file=s'    => \$file,
    'user=s'    => \$user,
    'pass=s'    => \$pass,
    'log=s'     => \$logfile,
    'timeout=i' => \$timeout,
    'help'      => \$help,
) or die "Error parsing options. Use --help for usage.\n";

if ($help || (!$host && !$file)) {
    print "Usage: $0 --host <ip> | --file <devices.txt> --user <username> [--pass <password>] [--log <outfile>] [--timeout <secs>]\n";
    exit 0;
}

die "Error: --user is required\n" unless $user;

# Prompt for password if not supplied (avoid plaintext on command line in prod)
unless ($pass) {
    print "Password for $user: ";
    system('stty', '-echo');
    chomp($pass = <STDIN>);
    system('stty', 'echo');
    print "\n";
}

my @devices;
if ($host) {
    push @devices, $host;
} elsif ($file) {
    open(my $fh, '<', $file) or die "Cannot open device file '$file': $!\n";
    while (<$fh>) {
        chomp;
        s/#.*//;    # strip comments
        s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
}

die "No devices to process.\n" unless @devices;

my $log_fh;
if ($logfile) {
    open($log_fh, '>', $logfile) or die "Cannot open log file '$logfile': $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
my $header = sprintf("%-20s %-16s %-19s %-6s %-20s\n", "Device", "IP Address", "MAC Address", "Age", "Interface");
my $divider = "-" x 85 . "\n";

print "\nARP Table Collection - $timestamp\n";
print $divider;
print $header;
print $divider;

if ($log_fh) {
    print $log_fh "ARP Table Collection - $timestamp\n";
    print $log_fh $divider;
    print $log_fh $header;
    print $log_fh $divider;
}

my ($total_entries, $failed_devices) = (0, 0);

for my $device (@devices) {
    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host        => $device,
            user        => $user,
            password    => $pass,
            raw_pty     => 1,
            timeout     => $timeout,
        );
        $ssh->login();
    };
    if ($@ || !$ssh) {
        my $err = "[$device] Connection/auth failed: $@";
        $err =~ s/\n/ /g;
        warn "$err\n";
        print $log_fh "$err\n" if $log_fh;
        $failed_devices++;
        next;
    }

    # Disable paging to get full output
    $ssh->send("terminal length 0");
    $ssh->waitfor('\s*#\s*$', $timeout) or warn "[$device] Prompt not found after terminal length 0\n";

    $ssh->send("show ip arp");
    my $output = $ssh->waitfor('\s*#\s*$', $timeout);
    unless (defined $output) {
        warn "[$device] Timeout waiting for 'show ip arp' output\n";
        $failed_devices++;
        next;
    }

    my $device_count = 0;
    for my $line (split /\n/, $output) {
        # Match ARP entries: Internet  10.0.0.1  5  aabb.cc00.0100  ARPA  GigabitEthernet0/0
        if ($line =~ /^Internet\s+([\d.]+)\s+(\d+|-)\s+([\w.]+)\s+ARPA\s+(\S+)/) {
            my ($ip, $age, $mac, $iface) = ($1, $2, $3, $4);
            my $row = sprintf("%-20s %-16s %-19s %-6s %-20s\n", $device, $ip, $mac, $age, $iface);
            print $row;
            print $log_fh $row if $log_fh;
            $device_count++;
            $total_entries++;
        }
    }

    if ($device_count == 0) {
        my $msg = sprintf("%-20s  (no ARP entries found or output parse error)\n", $device);
        print $msg;
        print $log_fh $msg if $log_fh;
    }

    $ssh->send("exit");
    $ssh->close() if $ssh->can('close');
}

my $summary = "\nSummary: $total_entries ARP entries collected from " . scalar(@devices) . " device(s). Failed: $failed_devices\n";
print $divider;
print $summary;
if ($log_fh) {
    print $log_fh $divider;
    print $log_fh $summary;
    close $log_fh;
    print "Output saved to: $logfile\n";
}