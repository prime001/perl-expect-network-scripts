#!/usr/bin/perl
#
# mac_table_collector.pl - Bulk MAC Address Table Collector
#
# PURPOSE:
#   Connects to one or more Cisco IOS switches via SSH and collects the full
#   MAC address table. Useful for device tracking, port security audits,
#   locating rogue devices, and verifying post-change network state.
#
# USAGE:
#   Single device:  perl mac_table_collector.pl -h 192.168.1.1
#   Device file:    perl mac_table_collector.pl -f switches.txt
#   With logging:   perl mac_table_collector.pl -f switches.txt -l mac_audit.log
#   Filter VLAN:    perl mac_table_collector.pl -h 192.168.1.1 -v 100
#   Find MAC:       perl mac_table_collector.pl -f switches.txt -m 0050.7966.6800
#
# PREREQUISITES:
#   cpan Net::SSH::Expect Getopt::Long
#   Credentials via environment: NET_USER, NET_PASS
#   Cisco IOS switches with SSH enabled and 'ip ssh version 2'
#
# OUTPUT:
#   DEVICE               VLAN   MAC                TYPE       PORT
#   192.168.1.10         100    0050.7966.6800     DYNAMIC    Gi0/1
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_log, $opt_vlan, $opt_mac, $opt_timeout);
$opt_timeout = 30;

GetOptions(
    'h|host=s'    => \$opt_host,
    'f|file=s'    => \$opt_file,
    'l|log=s'     => \$opt_log,
    'v|vlan=i'    => \$opt_vlan,
    'm|mac=s'     => \$opt_mac,
    't|timeout=i' => \$opt_timeout,
) or die "Usage: $0 [-h host|-f file] [-l log] [-v vlan] [-m mac] [-t timeout]\n";

die "ERROR: Specify -h <host> or -f <file>\n" unless $opt_host || $opt_file;

my $user = $ENV{NET_USER} or die "ERROR: Set NET_USER environment variable\n";
my $pass = $ENV{NET_PASS} or die "ERROR: Set NET_PASS environment variable\n";

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} elsif ($opt_file) {
    open(my $fh, '<', $opt_file) or die "ERROR: Cannot open $opt_file: $!\n";
    while (<$fh>) {
        chomp;
        push @devices, $_ unless /^\s*$/ || /^#/;
    }
    close $fh;
}

die "ERROR: No devices to process\n" unless @devices;

my $log_fh;
if ($opt_log) {
    open($log_fh, '>', $opt_log) or die "ERROR: Cannot open log $opt_log: $!\n";
}

sub output {
    my $line = shift;
    print $line;
    print $log_fh $line if $log_fh;
}

my $ts        = strftime("%Y-%m-%d %H:%M:%S", localtime);
my $separator = "-" x 74 . "\n";
my $header    = sprintf("%-20s %-6s %-18s %-10s %s\n", "DEVICE", "VLAN", "MAC", "TYPE", "PORT");

output("MAC Address Table Collection - $ts\n");
output($separator);
output($header);
output($separator);

my ($total_entries, $total_errors) = (0, 0);

for my $device (@devices) {
    my $ssh = Net::SSH::Expect->new(
        host       => $device,
        user       => $user,
        password   => $pass,
        raw_pty    => 1,
        timeout    => $opt_timeout,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=no',
    );

    eval {
        my $login = $ssh->login();
        die "Authentication failed or unexpected prompt\n" unless $login =~ /[>#]/;

        $ssh->exec("terminal length 0");

        my $cmd = $opt_vlan
            ? "show mac address-table vlan $opt_vlan"
            : "show mac address-table";

        my $output = $ssh->exec($cmd);
        my $count = 0;

        for my $line (split /\n/, $output) {
            next unless $line =~ /^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(DYNAMIC|STATIC|dynamic|static)\s+(\S+)/i;
            my ($vlan, $mac, $type, $port) = ($1, $2, uc($3), $4);
            next if $opt_mac && lc($mac) ne lc($opt_mac);
            output(sprintf("%-20s %-6s %-18s %-10s %s\n", $device, $vlan, $mac, $type, $port));
            $count++;
            $total_entries++;
        }

        output(sprintf("  [%-18s] %d entr%s\n", $device, $count, $count == 1 ? "y" : "ies"));
        $ssh->exec("exit");
    };

    if ($@) {
        my $err = $@;
        chomp $err;
        print STDERR "  [$device] ERROR: $err\n";
        print $log_fh "  [$device] ERROR: $err\n" if $log_fh;
        $total_errors++;
    }
}

output($separator);
output(sprintf("Devices: %d | Entries: %d | Errors: %d\n",
    scalar(@devices), $total_entries, $total_errors));

close $log_fh if $log_fh;
print "Log written to $opt_log\n" if $opt_log;

exit($total_errors > 0 ? 1 : 0);