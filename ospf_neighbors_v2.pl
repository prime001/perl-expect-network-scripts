#!/usr/bin/perl
#
# ospf_neighbor_monitor.pl - OSPF Neighbor Flap Detector
#
# Purpose:
#   Polls one or more Cisco IOS devices at a configurable interval and detects
#   OSPF neighbor state changes (e.g., FULL -> INIT, neighbor disappears).
#   Transient flaps that self-heal are missed by spot checks; this catches them.
#
# Usage:
#   ./ospf_neighbor_monitor.pl -h 192.168.1.1 [-u admin] [-i 60] [-c 20] [-l flaps.log]
#   ./ospf_neighbor_monitor.pl -f devices.txt  [-i 30]  [-c 0]  [-l flaps.log]
#
#   -h  Device IP/hostname
#   -f  File with devices (one per line: IP|username|password)
#   -u  SSH username (default: admin)
#   -i  Poll interval in seconds (default: 60)
#   -c  Poll count before exiting, 0 = run forever (default: 0)
#   -l  Log file path (optional; stdout always gets output)
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH key auth recommended; password read from device file or prompted.
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);
use Term::ReadKey;

our %opts;
getopts('h:f:u:i:c:l:', \%opts);

my $username    = $opts{u} || 'admin';
my $interval    = $opts{i} || 60;
my $max_polls   = $opts{c} // 0;
my $logfile     = $opts{l} || '';
my $log_fh;

if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log '$logfile': $!";
    $log_fh->autoflush(1);
}

sub emit {
    my ($msg) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    my $line = "[$ts] $msg";
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}

sub get_password {
    my ($host) = @_;
    print "Password for $username\@$host: ";
    ReadMode('noecho');
    my $pw = ReadLine(0);
    ReadMode('restore');
    print "\n";
    chomp $pw;
    return $pw;
}

sub fetch_neighbors {
    my ($host, $user, $pass) = @_;
    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => 15,
    );

    eval { $ssh->login() };
    if ($@) {
        emit("ERROR [$host] Login failed: $@");
        return undef;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#', 5);
    $ssh->send("show ip ospf neighbor");
    my $output = $ssh->waitfor('\$|#', 10);
    $ssh->send("exit");
    $ssh->close();

    my %neighbors;
    for my $line (split /\n/, $output) {
        # Neighbor ID    Pri   State     Dead Time   Address     Interface
        if ($line =~ /^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+/) {
            $neighbors{$1} = $2;
        }
    }
    return \%neighbors;
}

my @devices;
if ($opts{f}) {
    open(my $fh, '<', $opts{f}) or die "Cannot open device file '$opts{f}': $!";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^#/;
        my ($host, $user, $pass) = split /\|/, $_;
        push @devices, { host => $host, user => $user || $username, pass => $pass || '' };
    }
    close $fh;
} elsif ($opts{h}) {
    my $pass = get_password($opts{h});
    push @devices, { host => $opts{h}, user => $username, pass => $pass };
} else {
    die "Usage: $0 -h <host> | -f <devices_file> [-u user] [-i interval] [-c count] [-l logfile]\n";
}

my %prev_state;
my $polls = 0;

emit("Starting OSPF neighbor monitor: " . scalar(@devices) . " device(s), interval=${interval}s" .
     ($max_polls ? ", max_polls=$max_polls" : ", running indefinitely"));

while (1) {
    for my $dev (@devices) {
        my $host = $dev->{host};
        my $nbrs = fetch_neighbors($host, $dev->{user}, $dev->{pass});
        next unless defined $nbrs;

        my $prev = $prev_state{$host} || {};

        for my $nbr (sort keys %$nbrs) {
            my $state     = $nbrs->{$nbr};
            my $old_state = $prev->{$nbr};
            if (!defined $old_state) {
                emit("NEW    [$host] neighbor $nbr state=$state");
            } elsif ($old_state ne $state) {
                emit("CHANGE [$host] neighbor $nbr $old_state -> $state");
            }
        }
        for my $nbr (sort keys %$prev) {
            unless (exists $nbrs->{$nbr}) {
                emit("LOST   [$host] neighbor $nbr (was $prev->{$nbr}) -- no longer in table");
            }
        }

        $prev_state{$host} = $nbrs;
    }

    $polls++;
    last if $max_polls > 0 && $polls >= $max_polls;
    sleep $interval;
}

emit("Monitor complete after $polls poll(s).");
close $log_fh if $log_fh;