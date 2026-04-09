```perl
#!/usr/bin/perl
#
# ospf_flap_monitor.pl - OSPF Neighbor Flap Detection and State Monitor
#
# Purpose:
#   Polls one or more routers repeatedly and alerts when OSPF neighbor
#   adjacencies change state (flap detection). Useful for troubleshooting
#   unstable links or during maintenance windows to catch unintended drops.
#
# Usage:
#   ospf_flap_monitor.pl -h <host> [-u <user>] [-p <pass>] [-i <interval>]
#                        [-c <count>] [-l <logfile>]
#   ospf_flap_monitor.pl -f <device_file> [-u <user>] [-p <pass>]
#
#   -h  Target router IP or hostname
#   -f  File with one IP/hostname per line
#   -u  SSH username (default: $USER env var)
#   -p  SSH password (prompted if omitted)
#   -i  Poll interval in seconds (default: 30)
#   -c  Poll count before exit; 0 = run forever (default: 0)
#   -l  Optional log file path
#
# Prerequisites:
#   cpan install Net::SSH::Expect Getopt::Long Term::ReadKey
#
# Supported platforms:
#   Cisco IOS/IOS-XE (parses 'show ip ospf neighbor')
#
# Exit codes: 0 = clean exit, 1 = usage error, 2 = all hosts failed

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $logfile);
my $interval = 30;
my $count    = 0;

GetOptions(
    'h=s' => \$host,
    'f=s' => \$device_file,
    'u=s' => \$username,
    'p=s' => \$password,
    'i=i' => \$interval,
    'c=i' => \$count,
    'l=s' => \$logfile,
) or usage();

usage() unless $host || $device_file;

$username //= $ENV{USER} // 'admin';

unless ($password) {
    eval { require Term::ReadKey; Term::ReadKey->import('ReadMode') };
    print "SSH password: ";
    if ($@) {
        chomp($password = <STDIN>);
    } else {
        ReadMode('noecho');
        chomp($password = <STDIN>);
        ReadMode('restore');
        print "\n";
    }
}

my @devices = $host ? ($host) : do {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    map { chomp; $_ } grep { /\S/ && !/^#/ } <$fh>;
};

die "No devices to monitor.\n" unless @devices;

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!\n";
    $log_fh->autoflush(1);
}

sub ts { strftime('%Y-%m-%d %H:%M:%S', localtime) }

sub emit {
    my $msg = sprintf("[%s] %s\n", ts(), $_[0]);
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub get_neighbors {
    my ($dev) = @_;
    my $ssh = Net::SSH::Expect->new(
        host       => $dev,
        user       => $username,
        password   => $password,
        raw_pty    => 1,
        timeout    => 15,
    );
    eval { $ssh->login() };
    if ($@ || !defined $ssh) {
        emit("ERROR $dev: SSH login failed - $@");
        return undef;
    }
    $ssh->exec('terminal length 0');
    my $out = $ssh->exec('show ip ospf neighbor');
    $ssh->close();

    my %neighbors;
    for my $line (split /\n/, $out) {
        # Match: NeighborID  Pri  State  DeadTime  Address  Interface
        if ($line =~ /^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)/) {
            my ($nbr_id, $state, $nbr_addr, $iface) = ($1, $2, $3, $4);
            $neighbors{$nbr_id} = { state => $state, addr => $nbr_addr, iface => $iface };
        }
    }
    return \%neighbors;
}

my %prev_state;   # $prev_state{dev}{neighbor_id} = state string
my %flap_count;   # $prev_state{dev}{neighbor_id} = count

emit("Starting OSPF flap monitor: " . scalar(@devices) . " device(s), poll every ${interval}s" .
     ($count ? ", $count iterations" : ", continuous"));

my $iteration  = 0;
my $all_failed = 1;

while (1) {
    $iteration++;
    for my $dev (@devices) {
        my $neighbors = get_neighbors($dev);
        unless (defined $neighbors) {
            next;
        }
        $all_failed = 0;

        if (!exists $prev_state{$dev}) {
            # First poll - baseline
            my $n = scalar keys %$neighbors;
            emit("BASELINE $dev: $n OSPF neighbor(s) found");
            for my $id (sort keys %$neighbors) {
                my $r = $neighbors->{$id};
                emit("  $id  state=$r->{state}  addr=$r->{addr}  iface=$r->{iface}");
            }
            $prev_state{$dev} = { map { $_ => $neighbors->{$_}{state} } keys %$neighbors };
            next;
        }

        my $prev = $prev_state{$dev};

        # Detect new neighbors
        for my $id (sort keys %$neighbors) {
            unless (exists $prev->{$id}) {
                emit("NEW $dev: neighbor $id APPEARED  state=$neighbors->{$id}{state}  iface=$neighbors->{$id}{iface}");
            }
        }

        # Detect gone or state-changed neighbors
        for my $id (sort keys %$prev) {
            if (!exists $neighbors->{$id}) {
                $flap_count{$dev}{$id}++;
                emit("ALERT $dev: neighbor $id LOST (was $prev->{$id})  flaps=$flap_count{$dev}{$id}");
            } elsif ($neighbors->{$id}{state} ne $prev->{$id}) {
                $flap_count{$dev}{$id}++;
                emit("CHANGE $dev: neighbor $id  $prev->{$id} -> $neighbors->{$id}{state}  flaps=$flap_count{$dev}{$id}");
            }
        }

        $prev_state{$dev} = { map { $_ => $neighbors->{$_}{state} } keys %$neighbors };
    }

    last if $count && $iteration >= $count;
    sleep $interval;
}

emit("Monitor stopped after $iteration iteration(s).");
exit($all_failed ? 2 : 0);

sub usage {
    print "Usage: $0 -h <host>|-f <file> [-u user] [-p pass] [-i secs] [-c count] [-l logfile]\n";
    exit 1;
}
```