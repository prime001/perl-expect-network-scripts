```perl
#!/usr/bin/perl
# =============================================================================
# mac_table_audit.pl - MAC Address Table Audit via SSH
# =============================================================================
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches via SSH and collects MAC address
#   table data. Reports MAC counts per VLAN, flags VLANs with unusually high
#   MAC counts (possible loops/flooding), and identifies static MAC entries.
#   Useful for capacity planning, security audits, and loop detection.
#
# Usage:
#   Single device:  perl mac_table_audit.pl -h 192.168.1.1
#   Device list:    perl mac_table_audit.pl -f devices.txt
#   With logging:   perl mac_table_audit.pl -h 192.168.1.1 -l audit.log
#   Custom creds:   perl mac_table_audit.pl -h 192.168.1.1 -u admin -p secret
#   MAC threshold:  perl mac_table_audit.pl -h 192.168.1.1 -t 500
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH key auth or password auth to target devices
#   Cisco IOS/IOS-XE devices with 'show mac address-table' support
#
# Author: Network Automation Portfolio
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $device_file, $log_file, $username, $password, $threshold);
$username  = $ENV{NET_USER} // 'admin';
$password  = $ENV{NET_PASS} // 'cisco';
$threshold = 500;

GetOptions(
    'h|host=s'      => \$host_arg,
    'f|file=s'      => \$device_file,
    'l|log=s'       => \$log_file,
    'u|user=s'      => \$username,
    'p|pass=s'      => \$password,
    't|threshold=i' => \$threshold,
) or die "Usage: $0 -h <host> | -f <file> [-l logfile] [-u user] [-p pass] [-t threshold]\n";

die "Specify -h <host> or -f <file>\n" unless $host_arg || $device_file;

my @devices;
if ($host_arg)    { push @devices, $host_arg }
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if $_ }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub log_out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
log_out("=" x 60 . "\n");
log_out("MAC Address Table Audit - $ts\n");
log_out("=" x 60 . "\n");

for my $host (@devices) {
    log_out("\n[*] Connecting to $host ...\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $username,
        password    => $password,
        raw_pty     => 1,
        timeout     => 15,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        log_out("[ERROR] Failed to connect to $host: $@\n");
        next;
    }
    if ($login_output =~ /[Pp]assword|[Aa]uth/i && $login_output !~ /[>#]/) {
        log_out("[ERROR] Authentication failed on $host\n");
        next;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('\s*[>#]\s*$', 5);

    $ssh->send('show mac address-table');
    my $output = $ssh->waitfor('\s*[>#]\s*$', 30);

    unless ($output) {
        log_out("[ERROR] No response from $host\n");
        $ssh->close();
        next;
    }

    my (%vlan_macs, %static_macs, $total);
    for my $line (split /\n/, $output) {
        next unless $line =~ /^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\S+)\s+(\S+)/i;
        my ($vlan, $mac, $type, $port) = ($1, lc($2), $3, $4);
        $vlan_macs{$vlan}++;
        $total++;
        $static_macs{$vlan}++ if $type =~ /static/i;
    }

    log_out("\n  Host: $host\n");
    log_out("  Total MAC entries: $total\n");
    log_out(sprintf("  %-8s %-10s %-10s %s\n", 'VLAN', 'Dynamic', 'Static', 'Status'));
    log_out("  " . "-" x 45 . "\n");

    for my $vlan (sort { $a <=> $b } keys %vlan_macs) {
        my $count   = $vlan_macs{$vlan};
        my $static  = $static_macs{$vlan} // 0;
        my $dynamic = $count - $static;
        my $flag    = $count >= $threshold ? ' [!] HIGH - possible loop/flooding' : '';
        log_out(sprintf("  %-8s %-10s %-10s%s\n", $vlan, $dynamic, $static, $flag));
    }

    $ssh->send('exit');
    $ssh->close();
    log_out("\n  [OK] Audit complete for $host\n");
}

log_out("\n" . "=" x 60 . "\n");
log_out("Audit finished: " . strftime('%Y-%m-%d %H:%M:%S', localtime) . "\n");
close $log_fh if $log_fh;
```