Writing the Perl script now.

#!/usr/bin/perl
#
# cdp_lldp_neighbors.pl - CDP/LLDP Neighbor Discovery and Topology Tool
#
# Purpose:
#   Connects to one or more Cisco/IOS/NX-OS devices via SSH and collects
#   CDP and LLDP neighbor detail. Useful for topology documentation, verifying
#   physical adjacencies before maintenance windows, and validating cabling
#   after rack-and-stack work.
#
# Usage:
#   Single device:  ./cdp_lldp_neighbors.pl -h 10.0.0.1 -u admin -p secret
#   Device list:    ./cdp_lldp_neighbors.pl -f devices.txt -u admin -p secret
#   With log:       ./cdp_lldp_neighbors.pl -f devices.txt -u admin -p secret -o neighbors.log
#   Custom timeout: ./cdp_lldp_neighbors.pl -h 10.0.0.1 -u admin -p secret -t 60
#
# Device file format: one IP or hostname per line; lines starting with # are ignored
#
# Prerequisites:
#   Perl modules: Net::SSH::Expect, Getopt::Long
#   Devices must have SSH v2 enabled and CDP and/or LLDP configured
#
# Install modules: cpan Net::SSH::Expect

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case bundling);
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_out, $opt_help);
my $opt_timeout = 30;

GetOptions(
    'h|host=s'    => \$opt_host,
    'f|file=s'    => \$opt_file,
    'u|user=s'    => \$opt_user,
    'p|pass=s'    => \$opt_pass,
    'o|output=s'  => \$opt_out,
    't|timeout=i' => \$opt_timeout,
    'help'        => \$opt_help,
) or usage(1);

usage(0) if $opt_help;
usage(1) unless ($opt_host || $opt_file) && $opt_user && $opt_pass;

my @devices;
push @devices, $opt_host if $opt_host;

if ($opt_file) {
    open my $fh, '<', $opt_file or die "Cannot open device file '$opt_file': $!\n";
    while (<$fh>) {
        chomp; s/^\s+|\s+$//g;
        push @devices, $_ unless /^#/ || /^$/;
    }
    close $fh;
}
die "No devices to process.\n" unless @devices;

my $log_fh;
if ($opt_out) {
    open $log_fh, '>', $opt_out or die "Cannot write to '$opt_out': $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
log_out("=" x 65);
log_out("CDP/LLDP Neighbor Discovery  |  $ts");
log_out("Devices: " . scalar(@devices) . "  |  Timeout: ${opt_timeout}s");
log_out("=" x 65);

my ($ok, $fail) = (0, 0);

for my $device (@devices) {
    log_out("\nDevice: $device");
    log_out("-" x 45);

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $opt_user,
        password => $opt_pass,
        raw_pty  => 1,
        timeout  => $opt_timeout,
    );

    eval { $ssh->login() };
    if ($@) {
        (my $err = $@) =~ s/\n.*//s;
        log_out("  FAILED: $err");
        $fail++;
        next;
    }

    $ssh->exec("terminal length 0");
    $ssh->exec("terminal width 200");

    for my $proto ('cdp', 'lldp') {
        log_out("\n  [show $proto neighbors detail]");
        my $out = eval { $ssh->exec("show $proto neighbors detail") };
        if ($@) {
            log_out("  Timeout collecting $proto output");
            next;
        }
        my $printed = 0;
        for my $line (split /\r?\n/, $out) {
            next if $line =~ /^\s*$/ || $line =~ /show $proto neighbors|terminal/;
            log_out("  $line");
            $printed++;
        }
        log_out("  (no $proto neighbors or protocol not enabled)") unless $printed;
    }

    eval { $ssh->close() };
    $ok++;
}

log_out("\n" . "=" x 65);
log_out(sprintf("Complete: %d succeeded, %d failed, %d total", $ok, $fail, scalar(@devices)));
log_out("=" x 65);

if ($log_fh) {
    close $log_fh;
    print "Output written to: $opt_out\n";
}

sub log_out {
    my ($msg) = @_;
    print "$msg\n";
    print {$log_fh} "$msg\n" if $log_fh;
}

sub usage {
    my $exit = shift;
    print <<'USAGE';
Usage: cdp_lldp_neighbors.pl -h <host> | -f <file> -u <user> -p <pass> [options]

  -h, --host     Single device IP or hostname
  -f, --file     File with device list (one per line, # for comments)
  -u, --user     SSH username
  -p, --pass     SSH password
  -o, --output   Write output to log file (optional)
  -t, --timeout  SSH timeout in seconds (default: 30)
      --help     Show this help

USAGE
    exit $exit;
}