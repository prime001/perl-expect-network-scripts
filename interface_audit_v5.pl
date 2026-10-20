#!/usr/bin/perl
# =============================================================================
# cisco_interface_errors.pl - Interface Error Counter Audit for Cisco IOS
#
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE devices via SSH and audits
#   interface error counters (CRC errors, input errors, output drops,
#   interface resets). Flags any interface with non-zero counters so
#   engineers can quickly identify degraded or flapping links.
#
# Usage:
#   Single device:  ./cisco_interface_errors.pl -h 192.168.1.1
#   Device list:    ./cisco_interface_errors.pl -f devices.txt
#   With logging:   ./cisco_interface_errors.pl -h 192.168.1.1 -l audit.log
#   Custom timeout: ./cisco_interface_errors.pl -h 192.168.1.1 -t 30
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   NET_USER env var or -u flag for SSH username
#   Password via -p flag or pre-shared SSH keys (recommended)
#   Cisco IOS/IOS-XE with 'terminal length 0' support
#
# Device file format: one IP or hostname per line; # = comment
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $logfile, $user, $pass, $timeout, $help);
$user    = $ENV{NET_USER} // 'admin';
$timeout = 20;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$file,
    'l|log=s'     => \$logfile,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    't|timeout=i' => \$timeout,
    'help'        => \$help,
) or die "Option error. Use --help for usage.\n";

if ($help || (!$host && !$file)) {
    print "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile] [-t timeout]\n";
    exit 0;
}

my @devices = $host ? ($host) : read_device_file($file);
die "No devices to audit.\n" unless @devices;

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log '$logfile': $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
emit("=" x 62, $log_fh);
emit("Interface Error Counter Audit  --  $ts", $log_fh);
emit("=" x 62, $log_fh);

for my $dev (@devices) {
    audit_device($dev, $log_fh);
}

close($log_fh) if $log_fh;
exit 0;

# -----------------------------------------------------------------------------
sub audit_device {
    my ($device, $log_fh) = @_;

    emit("\n[+] $device", $log_fh);

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $device,
            user     => $user,
            defined($pass) ? (password => $pass) : (),
            raw_pty  => 1,
            timeout  => $timeout,
        );
    };
    if ($@ || !$ssh) {
        emit("    ERROR: could not initialize session: $@", $log_fh);
        return;
    }

    my $logged_in = eval { $ssh->login() };
    if ($@ || !$logged_in) {
        emit("    ERROR: authentication failed: $@", $log_fh);
        return;
    }

    $ssh->exec("terminal length 0");
    my $raw = eval { $ssh->exec("show interfaces") };
    if ($@ || !defined $raw) {
        emit("    ERROR: 'show interfaces' failed: $@", $log_fh);
        eval { $ssh->exec("exit") };
        return;
    }

    eval { $ssh->exec("exit") };

    my %errors = parse_errors($raw);

    unless (%errors) {
        emit("    OK -- no error counters detected on any interface.", $log_fh);
        return;
    }

    emit(sprintf("    %-32s %8s %8s %8s %8s",
        'Interface', 'InErr', 'CRC', 'OutDrop', 'Resets'), $log_fh);
    emit("    " . "-" x 68, $log_fh);

    for my $iface (sort keys %errors) {
        my $e = $errors{$iface};
        emit(sprintf("    %-32s %8d %8d %8d %8d",
            $iface,
            $e->{input_errors},
            $e->{crc},
            $e->{output_drops},
            $e->{resets},
        ), $log_fh);
    }
}

sub parse_errors {
    my ($output) = @_;
    my (%all, $cur);

    for my $line (split /\n/, $output) {
        if ($line =~ /^(\S+)\s+is\s+(?:up|down|administratively down)/) {
            $cur = $1;
            $all{$cur} = { input_errors => 0, crc => 0, output_drops => 0, resets => 0 };
            next;
        }
        next unless $cur;
        $all{$cur}{input_errors} = $1 if $line =~ /(\d+)\s+input errors/;
        $all{$cur}{crc}          = $1 if $line =~ /(\d+)\s+CRC/;
        $all{$cur}{output_drops} = $1 if $line =~ /(\d+)\s+output drops/;
        $all{$cur}{resets}       = $1 if $line =~ /(\d+)\s+interface resets/;
    }

    return map  { $_ => $all{$_} }
           grep { $all{$_}{input_errors} || $all{$_}{crc}
               || $all{$_}{output_drops} || $all{$_}{resets} }
           keys %all;
}

sub read_device_file {
    my ($path) = @_;
    open(my $fh, '<', $path) or die "Cannot open '$path': $!\n";
    my @devs = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
    return @devs;
}

sub emit {
    my ($msg, $fh) = @_;
    print "$msg\n";
    print $fh "$msg\n" if $fh;
}