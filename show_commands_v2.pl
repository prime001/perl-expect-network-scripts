#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# cpu_memory_health.pl - CPU and Memory Health Check via SSH
#
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE devices and collects CPU
#   utilization, memory statistics, and process table data. Useful for
#   capacity planning, incident triage, and routine health checks.
#
# Usage:
#   ./cpu_memory_health.pl --host 192.168.1.1 [options]
#   ./cpu_memory_health.pl --file devices.txt [options]
#
# Options:
#   --host <ip>       Single device IP or hostname
#   --file <path>     File with one device IP/hostname per line
#   --user <name>     SSH username (default: admin)
#   --pass <pass>     SSH password (prompted if omitted)
#   --log  <path>     Optional log file path
#   --timeout <sec>   SSH timeout in seconds (default: 15)
#   --threshold <pct> CPU % threshold to flag (default: 70)
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#
# Author:  Erik Anderson
# Version: 1.0
# =============================================================================

my ($opt_host, $opt_file, $opt_log, $opt_help);
my $opt_user      = 'admin';
my $opt_pass      = '';
my $opt_timeout   = 15;
my $opt_threshold = 70;

GetOptions(
    'host=s'      => \$opt_host,
    'file=s'      => \$opt_file,
    'user=s'      => \$opt_user,
    'pass=s'      => \$opt_pass,
    'log=s'       => \$opt_log,
    'timeout=i'   => \$opt_timeout,
    'threshold=i' => \$opt_threshold,
    'help'        => \$opt_help,
) or die "Invalid options. Use --help for usage.\n";

if ($opt_help || (!$opt_host && !$opt_file)) {
    print "Usage: $0 --host <ip> | --file <devices.txt> [--user <u>] [--pass <p>] [--log <f>] [--threshold <pct>]\n";
    exit 0;
}

if (!$opt_pass) {
    print "SSH password: ";
    system('stty', '-echo');
    chomp($opt_pass = <STDIN>);
    system('stty', 'echo');
    print "\n";
}

my @devices = $opt_host ? ($opt_host) : do {
    open(my $fh, '<', $opt_file) or die "Cannot open device file '$opt_file': $!\n";
    map { chomp; $_ } grep { /\S/ && !/^#/ } <$fh>;
};

die "No devices specified.\n" unless @devices;

my $log_fh;
if ($opt_log) {
    open($log_fh, '>>', $opt_log) or die "Cannot open log file '$opt_log': $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);

sub output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

output("=" x 70 . "\n");
output("CPU/Memory Health Check  |  $timestamp\n");
output("=" x 70 . "\n\n");

for my $device (@devices) {
    output("--- Device: $device ---\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $device,
            user        => $opt_user,
            password    => $opt_pass,
            raw_pty     => 1,
            timeout     => $opt_timeout,
        );
    };
    if ($@ || !$ssh) {
        output("  ERROR: Failed to create SSH session - $@\n\n");
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        output("  ERROR: Authentication failed or connection refused\n\n");
        next;
    }

    # Disable paging
    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|\#|>', 5);

    # CPU utilization
    output("  CPU Utilization:\n");
    $ssh->send("show processes cpu sorted | head 15");
    my $cpu_out = $ssh->waitfor('\$|\#|>', $opt_timeout);
    if ($cpu_out) {
        for my $line (split /\n/, $cpu_out) {
            next unless $line =~ /CPU|five|one minute|processes/i;
            $line =~ s/^\s+//;
            if ($line =~ /(\d+)%\/(\d+)%\/(\d+)%/) {
                my $five_min = $2;
                my $flag = ($five_min >= $opt_threshold) ? " *** HIGH ***" : "";
                output("    $line$flag\n");
            } else {
                output("    $line\n") if $line =~ /\S/;
            }
        }
    } else {
        output("    Timeout waiting for CPU data\n");
    }

    # Memory utilization
    output("  Memory Utilization:\n");
    $ssh->send("show processes memory sorted | head 10");
    my $mem_out = $ssh->waitfor('\$|\#|>', $opt_timeout);
    if ($mem_out) {
        for my $line (split /\n/, $mem_out) {
            if ($line =~ /Total|Used|Free|Processor|I\/O/i && $line =~ /\d/) {
                $line =~ s/^\s+//;
                output("    $line\n") if $line =~ /\S/;
            }
        }
    } else {
        output("    Timeout waiting for memory data\n");
    }

    $ssh->close();
    output("\n");
}

output("Check complete.\n");
close($log_fh) if $log_fh;