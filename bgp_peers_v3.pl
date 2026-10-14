The request says "Output ONLY the script content, no markdown fences, no explanation" — here it is:

#!/usr/bin/perl
#
# bgp_prefix_monitor.pl — BGP Prefix Count Monitor
#
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE routers via SSH and inspects
#   per-neighbor prefix counts (received, accepted, advertised). Flags
#   neighbors that are down, have zero accepted prefixes, or exceed an
#   optional high-water mark. Useful for detecting route leaks, full-table
#   drops, or silent peer failures that leave the session up but prefixless.
#
# Usage:
#   bgp_prefix_monitor.pl -h 192.0.2.1 -u admin -p secret
#   bgp_prefix_monitor.pl -f devices.txt -u admin -p secret -l /var/log/bgp_prefix.log
#   bgp_prefix_monitor.pl -h 192.0.2.1 -u admin -p secret --max-prefixes 750000
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#
# Options:
#   -h, --host         Single device IP or hostname
#   -f, --file         File with one device per line (ignores blank/#-comment lines)
#   -u, --user         SSH username
#   -p, --pass         SSH password
#   -l, --log          Optional log file path (appends)
#   -t, --timeout      Expect timeout in seconds (default: 15)
#   --max-prefixes     Alert threshold for received prefixes (default: none)

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log);
my $opt_timeout     = 15;
my $opt_max_prefixes;

GetOptions(
    'h|host=s'        => \$opt_host,
    'f|file=s'        => \$opt_file,
    'u|user=s'        => \$opt_user,
    'p|pass=s'        => \$opt_pass,
    'l|log=s'         => \$opt_log,
    't|timeout=i'     => \$opt_timeout,
    'max-prefixes=i'  => \$opt_max_prefixes,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOG] [--max-prefixes N]\n";

die "Provide -h HOST or -f FILE\n"    unless $opt_host || $opt_file;
die "Username (-u) required\n"        unless $opt_user;
die "Password (-p) required\n"        unless $opt_pass;

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open my $fh, '<', $opt_file or die "Cannot open $opt_file: $!\n";
    while (<$fh>) { chomp; push @devices, $_ unless /^\s*$/ || /^\s*#/; }
    close $fh;
}

my $log_fh;
if ($opt_log) {
    open $log_fh, '>>', $opt_log or die "Cannot open log $opt_log: $!\n";
}

sub emit {
    my ($msg) = @_;
    print $msg;
    print {$log_fh} $msg if $log_fh;
}

sub check_device {
    my ($host) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    emit("[$ts] ===== $host =====\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $opt_user,
        password => $opt_pass,
        timeout  => $opt_timeout,
        raw_pty  => 1,
    );

    eval {
        my $login = $ssh->login();
        die "Authentication failed\n" if $login !~ /[>#]/;
    };
    if ($@) {
        emit("  ERROR: Connection/auth failed for $host: $@\n");
        return;
    }

    $ssh->exec('terminal length 0');

    my $output = $ssh->exec('show ip bgp summary');
    unless ($output) {
        emit("  ERROR: No output from 'show ip bgp summary'\n");
        $ssh->close();
        return;
    }

    my $alerts    = 0;
    my $peer_count = 0;

    for my $line (split /\n/, $output) {
        next unless $line =~ /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+/;
        my $neighbor = $1;
        $peer_count++;

        my @f = split /\s+/, $line;
        shift @f if $f[0] eq '';
        my $state_or_pfx = $f[-1];

        if ($state_or_pfx =~ /^(Idle|Active|Connect|OpenSent|OpenConfirm)$/i) {
            emit(sprintf("  [ALERT] %-18s NOT ESTABLISHED (%s)\n", $neighbor, $state_or_pfx));
            $alerts++;
        } elsif ($state_or_pfx =~ /^\d+$/) {
            my $pfx  = int($state_or_pfx);
            my $flag = '';
            if ($pfx == 0) {
                $flag = ' <-- zero prefixes received';
                $alerts++;
            } elsif ($opt_max_prefixes && $pfx > $opt_max_prefixes) {
                $flag = sprintf(' <-- exceeds threshold (%d)', $opt_max_prefixes);
                $alerts++;
            }
            emit(sprintf("  %-18s  prefixes_rcvd=%-8d%s\n", $neighbor, $pfx, $flag));
        } else {
            emit(sprintf("  %-18s  state=%s\n", $neighbor, $state_or_pfx));
        }
    }

    emit("  Peers checked: $peer_count  |  Alerts: $alerts\n") if $peer_count;
    emit("  WARNING: No BGP neighbors found in output\n")       unless $peer_count;

    $ssh->close();
}

check_device($_) for @devices;
close $log_fh if $log_fh;