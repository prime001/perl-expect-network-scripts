#!/usr/bin/perl
#
# cdp_lldp_neighbors.pl - CDP/LLDP Neighbor Discovery and Topology Mapper
#
# PURPOSE:
#   Connects to Cisco IOS/NX-OS devices via SSH and collects CDP and LLDP
#   neighbor tables. Useful for discovering unknown devices, verifying topology
#   changes post-maintenance, and generating seed lists for network documentation.
#
# USAGE:
#   Single device:  ./cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./cdp_lldp_neighbors.pl -f devices.txt -u admin -p secret
#   With log file:  ./cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin -p secret -l out.log
#
# PREREQUISITES:
#   cpan Net::SSH::Expect Getopt::Long
#
# DEVICE FILE FORMAT:
#   One IP or hostname per line; lines starting with # are ignored.

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $username, $password, $logfile, $help);
my $timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$file,
    'u|user=s'     => \$username,
    'p|password=s' => \$password,
    'l|log=s'      => \$logfile,
    't|timeout=i'  => \$timeout,
    'help'         => \$help,
) or die "Error parsing options. Use --help for usage.\n";

if ($help || (!$host && !$file) || !$username || !$password) {
    print "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l <logfile>] [-t <sec>]\n";
    exit 1;
}

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $file) or die "Cannot open device file '$file': $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

die "No devices to process.\n" unless @devices;

my $log_fh;
if ($logfile) {
    open($log_fh, '>', $logfile) or die "Cannot open log file '$logfile': $!\n";
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
out("=" x 70);
out("CDP/LLDP Neighbor Discovery Report - $ts");
out("=" x 70);

for my $device (@devices) {
    out("\n[Device: $device]");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $device,
            user     => $username,
            password => $password,
            raw_pty  => 1,
            timeout  => $timeout,
        );
        $ssh->login();
    };
    if ($@) {
        (my $err = $@) =~ s/\n/ /g;
        out("  ERROR: Connection failed: $err");
        next;
    }

    eval { $ssh->exec("terminal length 0") };
    collect($ssh, $device, 'cdp',  'show cdp neighbors detail');
    collect($ssh, $device, 'lldp', 'show lldp neighbors detail');
    $ssh->close();
}

out("\n" . "=" x 70);
out("Scan complete.");
close($log_fh) if $log_fh;

sub collect {
    my ($ssh, $device, $proto, $cmd) = @_;

    my $raw;
    eval { $raw = $ssh->exec($cmd) };
    if ($@ || !defined $raw || length($raw) < 20) {
        out("  [$proto] Command failed or no output.");
        return;
    }
    if ($raw =~ /% invalid|not enabled|not running/i) {
        out("  [$proto] Not enabled on this device.");
        return;
    }

    my @neighbors = ($proto eq 'cdp') ? parse_cdp($raw) : parse_lldp($raw);

    if (!@neighbors) {
        out("  [$proto] No neighbors found.");
        return;
    }

    out(sprintf("  [$proto] %d neighbor(s):", scalar @neighbors));
    out(sprintf("    %-32s %-18s %-18s %-16s %s",
        "Device ID", "Local Port", "Remote Port", "Platform", "IP Address"));
    out("    " . "-" x 88);
    for my $n (@neighbors) {
        out(sprintf("    %-32s %-18s %-18s %-16s %s",
            substr($n->{device}  // 'unknown', 0, 31),
            substr($n->{local}   // 'unknown', 0, 17),
            substr($n->{remote}  // 'unknown', 0, 17),
            substr($n->{platform}// 'unknown', 0, 15),
            $n->{ip} // 'N/A'));
    }
}

sub parse_cdp {
    my ($raw) = @_;
    my @out;
    for my $block (split /[-]{10,}/, $raw) {
        next unless $block =~ /Device ID/i;
        my %n;
        ($n{device})   = $block =~ /Device ID:\s*(\S+)/i;
        ($n{ip})       = $block =~ /IP(?:v4)? [Aa]ddress:\s*(\d[\d.]+)/;
        ($n{platform}) = $block =~ /Platform:\s*([^,\n]+)/i;
        ($n{local})    = $block =~ /Interface:\s*(\S+)/i;
        ($n{remote})   = $block =~ /Port ID \(outgoing port\):\s*(\S+)/i;
        $n{platform} =~ s/\s+$// if $n{platform};
        push @out, \%n if $n{device};
    }
    return @out;
}

sub parse_lldp {
    my ($raw) = @_;
    my @out;
    for my $block (split /[-]{10,}/, $raw) {
        next unless $block =~ /System Name|Chassis id/i;
        my %n;
        ($n{device})   = $block =~ /System Name:\s*(\S+)/i;
        ($n{device}) //= do { my ($v) = $block =~ /Chassis id:\s*(\S+)/i; $v };
        ($n{ip})       = $block =~ /(\d{1,3}(?:\.\d{1,3}){3})/;
        ($n{platform}) = $block =~ /System Description:\s*([^\n]+)/i;
        ($n{local})    = $block =~ /Local Intf:\s*(\S+)/i;
        ($n{remote})   = $block =~ /Port id:\s*(\S+)/i;
        $n{platform}   = substr($n{platform} // '', 0, 40) if $n{platform};
        push @out, \%n if $n{device};
    }
    return @out;
}

sub out {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}