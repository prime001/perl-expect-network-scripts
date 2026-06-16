```perl
#!/usr/bin/perl
#
# ospf_neighbor_flap_monitor.pl
#
# Purpose:
#   Polls OSPF neighbor state on one or more Cisco IOS devices at a configurable
#   interval and reports any state changes (flaps, down events, new adjacencies).
#   Useful for catching transient OSPF instability that a one-shot check misses.
#
# Usage:
#   ./ospf_neighbor_flap_monitor.pl --host 192.168.1.1 [options]
#   ./ospf_neighbor_flap_monitor.pl --file devices.txt  [options]
#
#   Options:
#     --host HOST      Single device IP or hostname
#     --file FILE      Newline-separated list of host:user:pass entries
#     --user USER      SSH username (default: admin)
#     --pass PASS      SSH password (prompt if omitted)
#     --interval N     Seconds between polls (default: 30)
#     --count N        Number of poll cycles (default: 10; 0 = infinite)
#     --log FILE       Append output to log file in addition to STDOUT
#
# Prerequisites:
#   cpan Net::SSH::Expect Term::ReadKey
#
# Notes:
#   Tested against Cisco IOS 15.x and IOS-XE 16.x.
#   Expects an enable-mode prompt ending in '#'.
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX        qw(strftime);
use Term::ReadKey;

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log);
my $opt_interval = 30;
my $opt_count    = 10;

GetOptions(
    'host=s'     => \$opt_host,
    'file=s'     => \$opt_file,
    'user=s'     => \$opt_user,
    'pass=s'     => \$opt_pass,
    'interval=i' => \$opt_interval,
    'count=i'    => \$opt_count,
    'log=s'      => \$opt_log,
) or die "Usage: $0 --host HOST | --file FILE [--user U] [--pass P] [--interval N] [--count N] [--log FILE]\n";

die "ERROR: Provide --host or --file\n" unless $opt_host || $opt_file;

$opt_user //= 'admin';

unless ($opt_pass) {
    print "SSH password: ";
    ReadMode('noecho');
    chomp($opt_pass = <STDIN>);
    ReadMode('restore');
    print "\n";
}

my $log_fh;
if ($opt_log) {
    open $log_fh, '>>', $opt_log or die "Cannot open log $opt_log: $!";
    $log_fh->autoflush(1);
}

sub emit {
    my ($msg) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    my $line = "[$ts] $msg\n";
    print $line;
    print $log_fh $line if $log_fh;
}

sub parse_neighbors {
    my ($output) = @_;
    my %neighbors;
    for my $line (split /\n/, $output) {
        if ($line =~ /^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+\S+\s+(\S+)\s+(\S+)/) {
            my ($router_id, $priority, $state, $iface) = ($1, $2, $3, $4);
            $state =~ s|/.*||;  # strip DR/BDR qualifier
            $neighbors{$router_id} = { state => $state, iface => $iface };
        }
    }
    return %neighbors;
}

sub poll_device {
    my ($host, $user, $pass) = @_;
    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => 15,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    eval { $ssh->login() };
    if ($@) {
        emit("ERROR [$host]: SSH login failed — $@");
        return undef;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('#', 5);
    $ssh->send('show ip ospf neighbor');
    my $output = $ssh->waitfor('#', 15);
    $ssh->send('exit');

    return $output;
}

my @devices;
if ($opt_host) {
    push @devices, { host => $opt_host, user => $opt_user, pass => $opt_pass };
} else {
    open my $fh, '<', $opt_file or die "Cannot open $opt_file: $!";
    while (<$fh>) {
        chomp; next if /^\s*#/ || /^\s*$/;
        my ($h, $u, $p) = split /:/, $_, 3;
        push @devices, { host => $h, user => $u // $opt_user, pass => $p // $opt_pass };
    }
    close $fh;
}

my %prev_state;
my $cycle = 0;

emit("Starting OSPF flap monitor — interval=${opt_interval}s, cycles=" . ($opt_count ? $opt_count : 'infinite'));

while ($opt_count == 0 || $cycle < $opt_count) {
    $cycle++;
    for my $dev (@devices) {
        my $host = $dev->{host};
        my $raw  = poll_device($host, $dev->{user}, $dev->{pass});
        next unless defined $raw;

        my %curr = parse_neighbors($raw);

        unless (%{$prev_state{$host} // {}}) {
            # First poll — establish baseline
            my $count = scalar keys %curr;
            emit("BASELINE [$host]: $count neighbor(s) — " .
                 join(', ', map { "$_ ($curr{$_}{state}/$curr{$_}{iface})" } sort keys %curr));
            $prev_state{$host} = \%curr;
            next;
        }

        my %prev = %{$prev_state{$host}};
        my $changed = 0;

        for my $rid (sort keys %curr) {
            if (!exists $prev{$rid}) {
                emit("NEW [$host]: neighbor $rid came UP — $curr{$rid}{state} on $curr{$rid}{iface}");
                $changed++;
            } elsif ($prev{$rid}{state} ne $curr{$rid}{state}) {
                emit("FLAP [$host]: $rid $prev{$rid}{state} -> $curr{$rid}{state} on $curr{$rid}{iface}");
                $changed++;
            }
        }
        for my $rid (sort keys %prev) {
            unless (exists $curr{$rid}) {
                emit("DOWN [$host]: neighbor $rid ($prev{$rid}{state}/$prev{$rid}{iface}) disappeared");
                $changed++;
            }
        }

        emit("OK [$host]: cycle $cycle — no changes (" . scalar(keys %curr) . " neighbors stable)") unless $changed;
        $prev_state{$host} = \%curr;
    }

    last if $opt_count && $cycle >= $opt_count;
    sleep $opt_interval;
}

emit("Monitor complete after $cycle cycle(s).");
close $log_fh if $log_fh;
```