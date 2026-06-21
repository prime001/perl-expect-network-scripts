#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# bgp_peers_v3.pl — BGP Prefix Count Monitor with Threshold Alerting
#
# PURPOSE:
#   Connects to Cisco IOS/IOS-XE routers via SSH and collects per-peer BGP
#   prefix counts (received, accepted, advertised). Compares accepted prefix
#   counts against configurable warn/crit thresholds to detect route leaks,
#   peer misconfigurations, or abnormal withdrawal events.
#
# USAGE:
#   bgp_peers_v3.pl --host <ip>   [--user <u>] [--pass <p>] [--log <file>]
#   bgp_peers_v3.pl --file <list> [--user <u>] [--pass <p>] [--log <file>]
#
# OPTIONS:
#   --host     Single device IP or hostname
#   --file     File containing one device IP/hostname per line
#   --user     SSH username (default: admin)
#   --pass     SSH password (prompted if omitted)
#   --log      Append results to this log file
#   --warn     Accepted-prefix count warn threshold (default: 1000)
#   --crit     Accepted-prefix count crit threshold (default: 5000)
#   --timeout  SSH command timeout in seconds (default: 30)
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   SSH key or password auth to device; 'terminal length 0' must be settable.
#
# OUTPUT:
#   Tabular per-peer prefix summary with WARN/CRIT flags; exits 0 if clean.
# =============================================================================

my ($opt_host, $opt_file, $opt_log);
my $opt_user    = 'admin';
my $opt_pass    = '';
my $opt_warn    = 1000;
my $opt_crit    = 5000;
my $opt_timeout = 30;

GetOptions(
    'host=s'    => \$opt_host,
    'file=s'    => \$opt_file,
    'user=s'    => \$opt_user,
    'pass=s'    => \$opt_pass,
    'log=s'     => \$opt_log,
    'warn=i'    => \$opt_warn,
    'crit=i'    => \$opt_crit,
    'timeout=i' => \$opt_timeout,
) or die "Usage: $0 --host <ip>|--file <list> [options]\n";

die "Specify --host or --file\n" unless $opt_host || $opt_file;

unless ($opt_pass) {
    print "SSH password: ";
    system('stty', '-echo');
    chomp($opt_pass = <STDIN>);
    system('stty', 'echo');
    print "\n";
}

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open my $fh, '<', $opt_file or die "Cannot open $opt_file: $!\n";
    while (<$fh>) { chomp; push @devices, $_ if /\S/ && !/^#/; }
    close $fh;
}

my $log_fh;
if ($opt_log) {
    open $log_fh, '>>', $opt_log or die "Cannot open log $opt_log: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=== BGP Prefix Count Report — $ts ===\n");
output(sprintf "%-18s %-18s %-10s %-10s %-10s %s\n",
    'Device', 'Peer', 'Received', 'Accepted', 'Advertised', 'Status');
output('-' x 80 . "\n");

my $exit_code = 0;

for my $device (@devices) {
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
        output(sprintf "%-18s  ERROR: cannot create SSH session: %s\n", $device, $@ // '');
        $exit_code = 2;
        next;
    }

    my $login_ok = eval { $ssh->login() };
    if ($@ || !$login_ok) {
        output(sprintf "%-18s  ERROR: authentication failed\n", $device);
        $exit_code = 2;
        next;
    }

    $ssh->exec('terminal length 0');

    my $output = $ssh->exec('show ip bgp summary');
    unless (defined $output && $output =~ /\d+\.\d+\.\d+\.\d+/) {
        output(sprintf "%-18s  ERROR: no BGP summary output (BGP not running?)\n", $device);
        $exit_code = 1;
        $ssh->close();
        next;
    }

    my @peers;
    for my $line (split /\n/, $output) {
        # Cisco IOS BGP summary peer lines: IP, V, AS, MsgRcvd, MsgSent, TblVer, InQ, OutQ, Up/Down, State/PfxRcd
        next unless $line =~ /^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+)/;
        my ($peer, $pfx_rcd) = ($1, $2);
        next if $pfx_rcd =~ /[A-Za-z]/;  # skip peers not in Established state

        my $detail = $ssh->exec("show ip bgp neighbors $peer advertised-routes | include ^Total");
        my $advertised = 0;
        $advertised = $1 if defined $detail && $detail =~ /Total number of prefixes (\d+)/;

        my $detail2 = $ssh->exec("show ip bgp neighbors $peer | include ^  Prefixes Current");
        my ($accepted) = (0);
        if (defined $detail2 && $detail2 =~ /Prefixes Current:\s+(\d+)\s+(\d+)/) {
            $accepted = $1;
        } else {
            $accepted = $pfx_rcd;
        }

        push @peers, {
            peer       => $peer,
            received   => $pfx_rcd,
            accepted   => $accepted,
            advertised => $advertised,
        };
    }

    if (!@peers) {
        output(sprintf "%-18s  No established BGP peers found\n", $device);
        next;
    }

    for my $p (@peers) {
        my $status = 'OK';
        if ($p->{accepted} >= $opt_crit) {
            $status = 'CRIT';
            $exit_code = 2 if $exit_code < 2;
        } elsif ($p->{accepted} >= $opt_warn) {
            $status = 'WARN';
            $exit_code = 1 if $exit_code < 1;
        }

        output(sprintf "%-18s %-18s %-10s %-10s %-10s %s\n",
            $device, $p->{peer},
            $p->{received}, $p->{accepted}, $p->{advertised},
            $status);
    }

    $ssh->close();
}

output('-' x 80 . "\n");
output("Thresholds: WARN >= $opt_warn prefixes, CRIT >= $opt_crit prefixes\n");
output("Exit code: $exit_code\n");

close $log_fh if $log_fh;
exit $exit_code;

sub output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}