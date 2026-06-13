```perl
#!/usr/bin/perl
#
# ospf_flap_monitor.pl - OSPF Neighbor Flap Detection and State Change Tracker
#
# Purpose:
#   Polls a Cisco IOS/IOS-XE device repeatedly to detect OSPF neighbor state
#   changes (flaps). Unlike a one-shot neighbor check, this script monitors
#   adjacency stability over time — useful for diagnosing unstable links,
#   MTU mismatches, or timer inconsistencies in production environments.
#
# Usage:
#   ospf_flap_monitor.pl --host <IP> --user <user> --pass <password> [options]
#   ospf_flap_monitor.pl --file devices.txt --user <user> --pass <password>
#
# Options:
#   --host     Single device IP or hostname
#   --file     File with one device per line
#   --user     SSH username
#   --pass     SSH password
#   --interval Poll interval in seconds (default: 30)
#   --duration Total monitoring duration in seconds (default: 300)
#   --log      Path to output log file (optional)
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to device with 'show ip ospf neighbor' privilege

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $host_file, $user, $pass, $log_file);
my $interval = 30;
my $duration = 300;

GetOptions(
    'host=s'     => \$host,
    'file=s'     => \$host_file,
    'user=s'     => \$user,
    'pass=s'     => \$pass,
    'interval=i' => \$interval,
    'duration=i' => \$duration,
    'log=s'      => \$log_file,
) or die "Usage: $0 --host <IP> --user <u> --pass <p> [--interval 30] [--duration 300] [--log file]\n";

die "Provide --host or --file\n" unless $host || $host_file;
die "Provide --user and --pass\n" unless $user && $pass;

my @devices;
if ($host_file) {
    open my $fh, '<', $host_file or die "Cannot open $host_file: $!\n";
    @devices = grep { /\S/ } map { chomp; $_ } <$fh>;
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or warn "Cannot open log $log_file: $!\n";
}

sub ts { strftime('%Y-%m-%d %H:%M:%S', localtime) }

sub log_msg {
    my ($msg) = @_;
    my $line = "[" . ts() . "] $msg\n";
    print $line;
    print $log_fh $line if $log_fh;
}

sub get_neighbors {
    my ($ssh) = @_;
    my %neighbors;
    my $output = $ssh->exec('show ip ospf neighbor');
    for my $line (split /\n/, $output) {
        # Match: NeighborID  Pri  State  DeadTime  Address  Interface
        if ($line =~ /^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)/) {
            $neighbors{$1} = { state => $2, address => $3, interface => $4 };
        }
    }
    return %neighbors;
}

for my $device (@devices) {
    log_msg("=== Starting OSPF flap monitor on $device (${duration}s, ${interval}s interval) ===");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => 15,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    unless (eval { $ssh->login() }) {
        log_msg("ERROR: Cannot connect to $device: $@");
        next;
    }

    $ssh->exec('terminal length 0');

    my %prev;
    my $flap_count  = 0;
    my $start       = time;
    my $polls       = 0;

    while ((time - $start) < $duration) {
        my %curr = eval { get_neighbors($ssh) };
        if ($@) {
            log_msg("ERROR: Lost connection to $device: $@");
            last;
        }
        $polls++;

        # Detect disappearances and state changes
        for my $nbr (sort keys %prev) {
            if (!exists $curr{$nbr}) {
                log_msg("FLAP [$device] Neighbor $nbr ($prev{$nbr}{interface}) DROPPED from $prev{$nbr}{state}");
                $flap_count++;
            } elsif ($curr{$nbr}{state} ne $prev{$nbr}{state}) {
                log_msg("STATE [$device] Neighbor $nbr ($prev{$nbr}{interface}): $prev{$nbr}{state} -> $curr{$nbr}{state}");
                $flap_count++ if $curr{$nbr}{state} !~ /FULL/;
            }
        }
        # Detect new adjacencies
        for my $nbr (sort keys %curr) {
            if (!exists $prev{$nbr}) {
                log_msg("NEW [$device] Neighbor $nbr via $curr{$nbr}{interface} state=$curr{$nbr}{state}") if $polls > 1;
            }
        }

        if ($polls == 1) {
            log_msg("BASELINE [$device] " . scalar(keys %curr) . " neighbor(s): "
                . join(', ', map { "$_ ($curr{$_}{state}/$curr{$_}{interface})" } sort keys %curr));
        }

        %prev = %curr;
        sleep $interval if (time - $start) < $duration;
    }

    log_msg("=== DONE $device: $polls polls, $flap_count flap/change event(s) ===");
    $ssh->close() if $ssh->can('close');
}

close $log_fh if $log_fh;
```