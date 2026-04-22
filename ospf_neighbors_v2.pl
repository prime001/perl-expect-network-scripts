#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# ospf_neighbor_state_monitor.pl
#
# Purpose:
#   Monitor OSPF neighbor adjacency states and alert on non-FULL neighbors.
#   Compares current state against a saved baseline to detect state changes.
#   Useful for post-change validation and proactive adjacency monitoring.
#
# Usage:
#   Single device:  ./ospf_neighbor_state_monitor.pl --host 192.168.1.1
#   Device file:    ./ospf_neighbor_state_monitor.pl --file devices.txt
#   With baseline:  ./ospf_neighbor_state_monitor.pl --host 192.168.1.1 --save-baseline
#   With logging:   ./ospf_neighbor_state_monitor.pl --file devices.txt --log ospf_audit.log
#
# Device file format (one per line):
#   192.168.1.1
#   10.0.0.1
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH key auth or credentials via environment vars:
#     NET_USER, NET_PASS, NET_ENABLE
#
# Exit codes:
#   0 = all neighbors FULL
#   1 = one or more neighbors not FULL or state change detected
#   2 = connection/auth error
# =============================================================================

my ($host, $device_file, $log_file, $save_baseline, $baseline_dir);
my $timeout  = 30;
my $any_issue = 0;

GetOptions(
    'host=s'          => \$host,
    'file=s'          => \$device_file,
    'log=s'           => \$log_file,
    'save-baseline'   => \$save_baseline,
    'baseline-dir=s'  => \$baseline_dir,
    'timeout=i'       => \$timeout,
) or die "Usage: $0 --host <ip> | --file <file> [--log <file>] [--save-baseline] [--baseline-dir <dir>]\n";

die "Specify --host or --file\n" unless $host || $device_file;

my $user   = $ENV{NET_USER}   // die "Set NET_USER env var\n";
my $pass   = $ENV{NET_PASS}   // die "Set NET_PASS env var\n";
my $enable = $ENV{NET_ENABLE} // $pass;

$baseline_dir //= '/tmp/ospf_baselines';
mkdir $baseline_dir unless -d $baseline_dir;

my @devices = $host ? ($host) : do {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    map { chomp; $_ } grep { /\S/ && !/^#/ } <$fh>;
};

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);

sub log_output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

log_output("=" x 70 . "\n");
log_output("OSPF Neighbor State Monitor  -  $timestamp\n");
log_output("=" x 70 . "\n\n");

for my $device (@devices) {
    log_output("Device: $device\n");
    log_output("-" x 50 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password     => $pass,
        raw_pty      => 1,
        timeout      => $timeout,
        ssh_option   => '-o StrictHostKeyChecking=no -o ConnectTimeout=15',
    );

    my $login_output = eval { $ssh->login() };
    if ($@ || !defined $login_output) {
        log_output("  ERROR: SSH connection failed - $@\n\n");
        $any_issue = 2;
        next;
    }

    # Handle enable prompt
    if ($login_output =~ /Password:/i) {
        $ssh->send($enable);
        $ssh->waitfor('>\s*$|#\s*$', 5);
    }
    if ($login_output =~ />\s*$/) {
        $ssh->exec("enable");
        $ssh->send($enable);
        $ssh->waitfor('#\s*$', 5);
    }

    $ssh->exec("terminal length 0");

    my $neighbor_output = $ssh->exec("show ip ospf neighbor");
    my $interface_output = $ssh->exec("show ip ospf interface brief");

    $ssh->close();

    # Parse neighbor table
    my @neighbors;
    for my $line (split /\n/, $neighbor_output) {
        # Match: NeighborID  Pri  State  Dead Time  Address  Interface
        if ($line =~ /^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)/) {
            push @neighbors, {
                neighbor_id => $1,
                priority    => $2,
                state       => $3,
                dead_time   => $4,
                address     => $5,
                interface   => $6,
            };
        }
    }

    if (!@neighbors) {
        log_output("  WARNING: No OSPF neighbors found\n");
        $any_issue = 1;
    } else {
        my $baseline_file = "$baseline_dir/${device}_ospf_baseline.txt";
        my %baseline;

        if (-f $baseline_file) {
            open my $bfh, '<', $baseline_file or warn "Cannot read baseline: $!\n";
            while (<$bfh>) {
                chomp;
                my ($nid, $state) = split /\t/;
                $baseline{$nid} = $state if $nid && $state;
            }
            close $bfh;
        }

        printf "  %-18s %-6s %-16s %-13s %-18s %s\n",
            'Neighbor ID', 'Pri', 'State', 'Dead Time', 'Address', 'Interface';
        log_output(sprintf "  %-18s %-6s %-16s %-13s %-18s %s\n",
            'Neighbor ID', 'Pri', 'State', 'Dead Time', 'Address', 'Interface')
            if $log_fh;

        for my $n (@neighbors) {
            my $alert = '';
            if ($n->{state} !~ /FULL/) {
                $alert = ' <<< NOT FULL';
                $any_issue = 1;
            }
            if (%baseline && exists $baseline{$n->{neighbor_id}}) {
                if ($baseline{$n->{neighbor_id}} ne $n->{state}) {
                    $alert .= " [CHANGED from $baseline{$n->{neighbor_id}}]";
                    $any_issue = 1;
                }
            } elsif (%baseline) {
                $alert .= ' [NEW NEIGHBOR]';
            }

            my $line = sprintf "  %-18s %-6s %-16s %-13s %-18s %s%s\n",
                $n->{neighbor_id}, $n->{priority}, $n->{state},
                $n->{dead_time}, $n->{address}, $n->{interface}, $alert;
            log_output($line);
        }

        if ($save_baseline) {
            open my $bfh, '>', $baseline_file or warn "Cannot write baseline: $!\n";
            for my $n (@neighbors) {
                print $bfh "$n->{neighbor_id}\t$n->{state}\n";
            }
            close $bfh;
            log_output("  [Baseline saved to $baseline_file]\n");
        }

        # Show OSPF interface summary
        log_output("\n  OSPF Interface Summary:\n");
        for my $line (split /\n/, $interface_output) {
            next unless $line =~ /^\S+\d+/;
            log_output("    $line\n");
        }
    }

    log_output("\n");
}

log_output("=" x 70 . "\n");
log_output("Completed: $timestamp\n");
log_output("Status: " . ($any_issue == 0 ? "ALL NEIGHBORS FULL" :
                         $any_issue == 1 ? "ISSUES DETECTED"    :
                                           "CONNECTION ERRORS") . "\n");
log_output("=" x 70 . "\n");

close $log_fh if $log_fh;
exit($any_issue ? 1 : 0);