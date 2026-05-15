#!/usr/bin/perl
#
# cdp_lldp_neighbors.pl - CDP/LLDP Neighbor Discovery Tool
#
# PURPOSE:
#   Connects to Cisco IOS/IOS-XE devices via SSH and collects CDP and LLDP
#   neighbor detail for topology mapping and network documentation.
#
# USAGE:
#   Single device:  perl cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    perl cdp_lldp_neighbors.pl -f devices.txt -u admin -p secret
#   With log file:  perl cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin -p secret -l out.log
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   cpan Getopt::Long
#
# DEVICE FILE FORMAT:
#   One IP or hostname per line. Lines beginning with # are ignored.
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $device_file, $username, $password, $log_file, $help);
my $timeout = 20;

GetOptions(
    'h|host=s'    => \$host_arg,
    'f|file=s'    => \$device_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'l|log=s'     => \$log_file,
    't|timeout=i' => \$timeout,
    'help'        => \$help,
) or die "Option error. Use --help for usage.\n";

if ($help || !$username || !$password || (!$host_arg && !$device_file)) {
    print "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l <logfile>] [-t <secs>]\n";
    exit 1;
}

my @devices;
if ($host_arg) {
    @devices = ($host_arg);
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    @devices = grep { !/^#/ && !/^\s*$/ } map { chomp; $_ } <$fh>;
    close($fh);
}
die "No devices to process.\n" unless @devices;

my $log_fh;
if ($log_file) {
    open($log_fh, '>', $log_file) or die "Cannot open log $log_file: $!\n";
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
log_out($log_fh, "=" x 68);
log_out($log_fh, "CDP/LLDP Neighbor Discovery Report  |  $ts");
log_out($log_fh, "=" x 68);

for my $device (@devices) {
    $device =~ s/^\s+|\s+$//g;
    poll_device($device);
}

close($log_fh) if $log_fh;

sub poll_device {
    my ($host) = @_;
    log_out($log_fh, "\n>>> $host");

    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $username,
        password => $password,
        timeout  => $timeout,
        raw_pty  => 1,
    );

    my $banner;
    eval { $banner = $ssh->login() };
    if ($@ || !defined $banner) {
        log_out($log_fh, "  ERROR: SSH connection failed - " . ($@ =~ s/\n.*//sr || 'timeout'));
        return;
    }
    if ($banner =~ /[Pp]assword|denied/i && $banner !~ /[>#]/) {
        log_out($log_fh, "  ERROR: Authentication failed");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\s*[>#]\s*$', $timeout) or do {
        log_out($log_fh, "  ERROR: No prompt after terminal length 0");
        $ssh->close();
        return;
    };

    # CDP
    log_out($log_fh, "\n  [ CDP Neighbors ]");
    $ssh->send("show cdp neighbors detail");
    my $cdp = $ssh->waitfor('\s*[>#]\s*$', $timeout);
    if ($cdp && $cdp !~ /Invalid|% CDP|not enabled/) {
        parse_cdp($cdp);
    } else {
        log_out($log_fh, "  CDP not available or not enabled on this device");
    }

    # LLDP
    log_out($log_fh, "\n  [ LLDP Neighbors ]");
    $ssh->send("show lldp neighbors detail");
    my $lldp = $ssh->waitfor('\s*[>#]\s*$', $timeout);
    if ($lldp && $lldp !~ /Invalid|% LLDP|not enabled/) {
        parse_lldp($lldp);
    } else {
        log_out($log_fh, "  LLDP not available or not enabled on this device");
    }

    $ssh->send("exit");
    $ssh->close();
}

sub parse_cdp {
    my ($raw) = @_;
    my (@entries, %cur);
    for my $line (split /\n/, $raw) {
        if ($line =~ /^Device ID:\s*(\S+)/) {
            push @entries, {%cur} if %cur;
            %cur = (id => $1);
        } elsif ($line =~ /IP[Vv]?4? address:\s*([\d.]+)/i) { $cur{ip}  //= $1 }
          elsif ($line =~ /Interface:\s*(\S+),.*Port ID.*:\s*(\S+)/)  { @cur{qw(lif rif)} = ($1,$2) }
          elsif ($line =~ /Platform:\s*([^,]+)/)                      { $cur{plat} = $1 }
    }
    push @entries, {%cur} if %cur;
    if (@entries) {
        log_out($log_fh, sprintf("  %-32s %-17s %-20s %-18s %s",
            "Device ID","IP","Local Intf","Remote Intf","Platform"));
        log_out($log_fh, "  " . "-" x 95);
        log_out($log_fh, sprintf("  %-32s %-17s %-20s %-18s %s",
            $_->{id}//'?', $_->{ip}//'N/A', $_->{lif}//'N/A',
            $_->{rif}//'N/A', $_->{plat}//'')) for @entries;
        log_out($log_fh, "  Total: " . @entries . " CDP neighbor(s)");
    } else {
        log_out($log_fh, "  No CDP neighbors found");
    }
}

sub parse_lldp {
    my ($raw) = @_;
    my (@entries, %cur);
    for my $line (split /\n/, $raw) {
        if ($line =~ /^Local Intf:\s*(\S+)/) {
            push @entries, {%cur} if %cur;
            %cur = (lif => $1);
        } elsif ($line =~ /System Name:\s*(.+)/)    { $cur{name} = $1 }
          elsif ($line =~ /Port id:\s*(.+)/)         { $cur{rif}  = $1 }
          elsif ($line =~ /\bIP:\s*([\d.]+)/)        { $cur{ip}  //= $1 }
          elsif ($line =~ /Management.*?([\d]{1,3}(?:\.[\d]{1,3}){3})/) { $cur{ip} //= $1 }
    }
    push @entries, {%cur} if %cur;
    if (@entries) {
        log_out($log_fh, sprintf("  %-32s %-17s %-20s %s",
            "System Name","IP","Local Intf","Remote Port"));
        log_out($log_fh, "  " . "-" x 80);
        log_out($log_fh, sprintf("  %-32s %-17s %-20s %s",
            $_->{name}//'?', $_->{ip}//'N/A',
            $_->{lif}//'N/A', $_->{rif}//'N/A')) for @entries;
        log_out($log_fh, "  Total: " . @entries . " LLDP neighbor(s)");
    } else {
        log_out($log_fh, "  No LLDP neighbors found");
    }
}

sub log_out {
    my ($fh, $msg) = @_;
    print "$msg\n";
    print $fh "$msg\n" if $fh;
}