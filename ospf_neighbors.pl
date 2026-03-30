#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# ospf-neighbors.pl - OSPF Neighbor State Collector
#
# Purpose:
#   Connects to one or more network devices via SSH and collects OSPF neighbor
#   information. Useful for rapid verification during maintenance windows,
#   post-change validation, or periodic health checks.
#
# Usage:
#   Single device:   ./ospf-neighbors.pl -h 192.168.1.1
#   Multiple devices: ./ospf-neighbors.pl -f devices.txt
#   With logging:    ./ospf-neighbors.pl -f devices.txt -l ospf_check.log
#   Custom creds:    ./ospf-neighbors.pl -h 10.0.0.1 -u admin -p secretpass
#
# Device file format (one IP or hostname per line, # for comments):
#   192.168.1.1
#   router2.example.com
#   # 10.0.0.5  (skipped)
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to target devices (Cisco IOS/IOS-XE/NX-OS supported)
#   Credentials with at least read-only privilege level
#
# Exit codes:
#   0 - All neighbors FULL/2WAY
#   1 - One or more neighbors in non-converged state
#   2 - Script error (bad args, no devices reachable)
# =============================================================================

my ($host, $device_file, $log_file, $username, $password, $timeout, $help);
$username = $ENV{NET_USER} // 'admin';
$password = $ENV{NET_PASS} // '';
$timeout  = 15;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'l|log=s'      => \$log_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    't|timeout=i'  => \$timeout,
    'help'         => \$help,
) or die "Error parsing options. Use --help for usage.\n";

if ($help) {
    system("grep '^#' $0 | head -30 | sed 's/^# \\?//'");
    exit 0;
}

unless ($host || $device_file) {
    die "Error: specify -h <host> or -f <device_file>\n";
}

unless ($password) {
    print "Password for $username: ";
    system('stty -echo');
    chomp($password = <STDIN>);
    system('stty echo');
    print "\n";
}

my @devices;
if ($host) {
    push @devices, $host;
}
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

my $ts        = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $non_full  = 0;
my $failed    = 0;

sub log_output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

log_output("=" x 70 . "\n");
log_output("OSPF Neighbor Check  |  $ts\n");
log_output("=" x 70 . "\n");

for my $device (@devices) {
    log_output("\n[ $device ]\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $username,
        password    => $password,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        log_output("  ERROR: SSH login failed - $@\n");
        $failed++;
        next;
    }

    # Disable paging so we get complete output
    $ssh->send('terminal length 0');
    $ssh->waitfor('\$|#|>', 5);

    $ssh->send('show ip ospf neighbor');
    my $output = $ssh->waitfor('\$|#|>', $timeout);

    unless (defined $output && length $output > 10) {
        log_output("  ERROR: No output received (timeout or empty response)\n");
        $failed++;
        $ssh->close();
        next;
    }

    my $neighbor_count = 0;
    my @problem_neighbors;

    for my $line (split /\n/, $output) {
        # Match OSPF neighbor table lines: neighbor-id, pri, state, ...
        if ($line =~ /^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+/) {
            my ($nbr_id, $pri, $state) = ($1, $2, $3);
            $neighbor_count++;
            my $flag = ($state =~ /^FULL|2WAY/) ? '  OK' : 'WARN';
            log_output(sprintf("  %-5s  %-16s  Pri:%-3s  State: %s\n",
                               $flag, $nbr_id, $pri, $state));
            push @problem_neighbors, "$nbr_id ($state)"
                unless $state =~ /^FULL|2WAY/;
        }
    }

    if ($neighbor_count == 0) {
        log_output("  WARN: No OSPF neighbors found\n");
        $non_full++;
    } elsif (@problem_neighbors) {
        log_output("  SUMMARY: $neighbor_count neighbor(s), "
                   . scalar(@problem_neighbors) . " non-converged: "
                   . join(', ', @problem_neighbors) . "\n");
        $non_full++;
    } else {
        log_output("  SUMMARY: $neighbor_count neighbor(s), all converged\n");
    }

    $ssh->close();
}

log_output("\n" . "=" x 70 . "\n");
log_output("Devices checked: " . scalar(@devices)
           . "  |  Failed connections: $failed"
           . "  |  Non-converged: $non_full\n");
log_output("=" x 70 . "\n");

close $log_fh if $log_fh;

exit(($failed == scalar(@devices)) ? 2 : ($non_full ? 1 : 0));