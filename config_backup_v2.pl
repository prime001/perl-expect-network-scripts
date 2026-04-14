```perl
#!/usr/bin/perl
#
# cdp_lldp_neighbors.pl - CDP/LLDP Neighbor Discovery Tool
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and collects CDP and LLDP
#   neighbor information. Useful for topology documentation, verifying cabling,
#   and discovering connected devices during audits or incident response.
#
# Usage:
#   Single device:  ./cdp_lldp_neighbors.pl -h 192.168.1.1
#   Device file:    ./cdp_lldp_neighbors.pl -f devices.txt
#   With logging:   ./cdp_lldp_neighbors.pl -f devices.txt -l neighbors.log
#   Custom creds:   ./cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin -p secret
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access enabled on target devices
#   Account with 'show cdp neighbors detail' and 'show lldp neighbors detail' privilege
#
# Device file format (one per line, lines starting with # are ignored):
#   192.168.1.1
#   switch-core-01.example.com
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $device_file, $log_file);
my $username = $ENV{NET_USER} // 'admin';
my $password = $ENV{NET_PASS} // 'cisco';
my $timeout  = 20;

GetOptions(
    'h|host=s'     => \$host_arg,
    'f|file=s'     => \$device_file,
    'l|log=s'      => \$log_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 [-h host] [-f file] [-l logfile] [-u user] [-p pass]\n";

die "Specify -h <host> or -f <file>\n" unless $host_arg || $device_file;

my @devices;
if ($host_arg) {
    push @devices, $host_arg;
}
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^\s*#/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>', $log_file) or die "Cannot open log $log_file: $!\n";
}

sub logprint {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
logprint("=" x 70 . "\n");
logprint("CDP/LLDP Neighbor Discovery  |  $timestamp\n");
logprint("=" x 70 . "\n\n");

for my $device (@devices) {
    logprint("Device: $device\n");
    logprint("-" x 50 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $username,
        password     => $password,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        logprint("  [ERROR] SSH connection failed: " . ($@ || 'unknown error') . "\n\n");
        next;
    }
    if ($login_output =~ /[Pp]assword/i || $login_output =~ /[Aa]uth/i) {
        logprint("  [ERROR] Authentication failed for $device\n\n");
        next;
    }

    # Disable paging
    $ssh->exec("terminal length 0");

    # Collect CDP neighbors
    logprint("  CDP Neighbors:\n");
    my $cdp_output = $ssh->exec("show cdp neighbors detail");
    if (!defined $cdp_output || $cdp_output =~ /invalid|error|not enabled/i) {
        logprint("    CDP not available or not enabled\n");
    } else {
        my @cdp_entries = split(/[-]{10,}/, $cdp_output);
        my $found = 0;
        for my $entry (@cdp_entries) {
            next unless $entry =~ /Device ID/i;
            $found = 1;
            my ($device_id)   = $entry =~ /Device ID:\s*(\S+)/i;
            my ($ip_addr)     = $entry =~ /IP address:\s*(\S+)/i;
            my ($platform)    = $entry =~ /Platform:\s*([^,]+)/i;
            my ($local_intf)  = $entry =~ /Interface:\s*(\S+)/i;
            my ($remote_intf) = $entry =~ /Port ID.*?:\s*(\S+)/i;
            logprint(sprintf("    %-30s %-16s %-20s %s -> %s\n",
                $device_id // 'unknown',
                $ip_addr   // 'no-ip',
                $platform  // 'unknown',
                $local_intf  // '?',
                $remote_intf // '?'));
        }
        logprint("    No CDP neighbors found\n") unless $found;
    }

    # Collect LLDP neighbors
    logprint("  LLDP Neighbors:\n");
    my $lldp_output = $ssh->exec("show lldp neighbors detail");
    if (!defined $lldp_output || $lldp_output =~ /invalid|error|not enabled/i) {
        logprint("    LLDP not available or not enabled\n");
    } else {
        my @lldp_entries = split(/[-]{10,}/, $lldp_output);
        my $found = 0;
        for my $entry (@lldp_entries) {
            next unless $entry =~ /System Name/i;
            $found = 1;
            my ($sys_name)   = $entry =~ /System Name:\s*(\S+)/i;
            my ($mgmt_ip)    = $entry =~ /Management Addresses.*?IP:\s*(\S+)/si;
            my ($local_intf) = $entry =~ /Local Intf:\s*(\S+)/i;
            my ($port_id)    = $entry =~ /Port id:\s*(\S+)/i;
            logprint(sprintf("    %-30s %-16s %s -> %s\n",
                $sys_name   // 'unknown',
                $mgmt_ip    // 'no-ip',
                $local_intf // '?',
                $port_id    // '?'));
        }
        logprint("    No LLDP neighbors found\n") unless $found;
    }

    $ssh->close();
    logprint("\n");
}

logprint("Discovery complete.\n");
close $log_fh if $log_fh;
```