#!/usr/bin/perl
#
# mac_table_audit.pl - MAC Address Table Collection and Analysis
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches via SSH and collects MAC address
#   table data. Reports per-VLAN MAC populations, flags static entries for
#   security review, and identifies MACs appearing in multiple VLANs which
#   may indicate misconfigurations or unauthorized bridging.
#
# Usage:
#   ./mac_table_audit.pl -h <host> -u <user> -p <pass> [options]
#   ./mac_table_audit.pl -f <hostfile> -u <user> -p <pass> [options]
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to target Cisco IOS/IOS-XE devices
#
# Options:
#   -h  Single target device IP or hostname
#   -f  File with one device per line (# comments supported)
#   -u  SSH username
#   -p  SSH password
#   -e  Enable password (if required)
#   -l  Append results to log file

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $hostfile, $user, $pass, $enable, $logfile, $help);

GetOptions(
    'h|host=s'   => \$host,
    'f|file=s'   => \$hostfile,
    'u|user=s'   => \$user,
    'p|pass=s'   => \$pass,
    'e|enable=s' => \$enable,
    'l|log=s'    => \$logfile,
    'help'       => \$help,
) or usage();

usage() if $help || (!$host && !$hostfile) || !$user || !$pass;

my @hosts = $host ? ($host) : ();
if ($hostfile) {
    open my $fh, '<', $hostfile or die "Cannot open $hostfile: $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        push @hosts, $_ if length $_;
    }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open $logfile: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=" x 62);
out("MAC Address Table Audit  --  $ts");
out("=" x 62);

audit_device($_) for @hosts;

close $log_fh if $log_fh;

sub audit_device {
    my ($device) = @_;
    out("\n[*] Connecting to $device ...");

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $user,
        password => $pass,
        raw_pty  => 1,
        timeout  => 15,
    );

    my $banner;
    eval { $banner = $ssh->login() };
    if ($@ || !defined $banner) {
        out("[-] $device: connection failed -- $@");
        return;
    }

    if ($enable && $banner =~ />\s*$/) {
        $ssh->send("enable");
        if ($ssh->waitfor('Password:', 8)) {
            $ssh->send($enable);
            unless ($ssh->waitfor('#', 8)) {
                out("[-] $device: enable auth failed");
                $ssh->close(); return;
            }
        }
    }

    $ssh->exec("terminal length 0");

    my $raw = $ssh->exec("show mac address-table");
    if (!defined $raw || $raw !~ /[0-9a-f]{4}\.[0-9a-f]{4}/i) {
        $raw = $ssh->exec("show mac-address-table");
    }
    $ssh->close();

    parse_report($device, $raw // '');
}

sub parse_report {
    my ($device, $raw) = @_;

    my (%vlan_count, %mac_vlans, %mac_type);

    for my $line (split /\n/, $raw) {
        next unless $line =~ /^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(DYNAMIC|STATIC|dynamic|static)\s+(\S+)/i;
        my ($vlan, $mac, $type) = ($1, lc $2, uc $3);
        $vlan_count{$vlan}++;
        push @{$mac_vlans{$mac}}, $vlan unless grep { $_ eq $vlan } @{$mac_vlans{$mac}};
        $mac_type{$mac} = $type;
    }

    my $total = 0;
    $total += $_ for values %vlan_count;

    out("\n  Device : $device");
    out("  Entries: $total");

    if ($total == 0) {
        out("  WARN: no MAC entries parsed -- verify IOS version / output format");
        return;
    }

    out("\n  Per-VLAN MAC count:");
    for my $vlan (sort { $a <=> $b } keys %vlan_count) {
        out(sprintf("    VLAN %-5s  %4d MACs", $vlan, $vlan_count{$vlan}));
    }

    my @static = sort grep { $mac_type{$_} eq 'STATIC' } keys %mac_type;
    if (@static) {
        out("\n  Static entries (" . scalar(@static) . ") -- review for port-security / sticky:");
        out(sprintf("    %-20s  VLAN(s)", "MAC")) ;
        for my $mac (@static) {
            out(sprintf("    %-20s  %s", $mac, join(', ', sort { $a <=> $b } @{$mac_vlans{$mac}})));
        }
    }

    my @dup = sort grep { @{$mac_vlans{$_}} > 1 } keys %mac_vlans;
    if (@dup) {
        out("\n  MACs in multiple VLANs (" . scalar(@dup) . ") -- investigate:");
        for my $mac (@dup) {
            out(sprintf("    %-20s  VLANs: %s  [%s]",
                $mac, join(', ', sort { $a <=> $b } @{$mac_vlans{$mac}}), $mac_type{$mac}));
        }
    } else {
        out("\n  No MACs seen in multiple VLANs.");
    }
}

sub out {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}

sub usage {
    print <<'END';
Usage: mac_table_audit.pl -h <host>|-f <file> -u <user> -p <pass> [options]

  -h, --host    Target device (IP or hostname)
  -f, --file    File of devices, one per line
  -u, --user    SSH username
  -p, --pass    SSH password
  -e, --enable  Enable password
  -l, --log     Append output to log file
      --help    This help

END
    exit 1;
}