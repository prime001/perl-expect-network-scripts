#!/usr/bin/perl
#
# cdp_lldp_neighbors.pl - CDP/LLDP Neighbor Discovery via SSH
#
# PURPOSE:
#   Connects to one or more network devices and collects CDP and LLDP neighbor
#   tables. Useful for topology mapping, change verification, and auditing
#   undocumented adjacencies. Outputs structured neighbor data to STDOUT
#   and optionally a timestamped log file.
#
# USAGE:
#   Single device:   ./cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin [-p password] [-l logfile]
#   Device list:     ./cdp_lldp_neighbors.pl -f devices.txt -u admin [-p password] [-l logfile]
#   With key auth:   ./cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin -k
#
# PREREQUISITES:
#   - Perl modules: Expect, Getopt::Std, Term::ReadKey (CPAN)
#   - SSH access to target devices with 'show cdp neighbors detail' or
#     'show lldp neighbors detail' privilege
#   - Cisco IOS/IOS-XE/NX-OS targets; LLDP fallback for non-Cisco
#
# OPTIONS:
#   -h <host>     Single device IP or hostname
#   -f <file>     File containing one device per line (IP or hostname)
#   -u <user>     SSH username
#   -p <pass>     SSH password (omit to be prompted; use -k for key auth)
#   -k            Use SSH key authentication (no password needed)
#   -l <logfile>  Write output to logfile in addition to STDOUT
#   -t <seconds>  Per-command timeout (default: 30)
#   -v            Verbose: show raw device output
#

use strict;
use warnings;
use Expect;
use Getopt::Std;
use POSIX qw(strftime);
use Term::ReadKey qw(ReadMode ReadLine);

$Getopt::Std::STANDARD_HELP_VERSION = 1;

my %opts;
getopts('h:f:u:p:kl:t:v', \%opts);

unless (($opts{h} || $opts{f}) && $opts{u}) {
    print STDERR "Usage: $0 -h <host>|-f <file> -u <user> [-p <pass>|-k] [-l <log>] [-t <timeout>] [-v]\n";
    exit 1;
}

my $timeout  = $opts{t} || 30;
my $username = $opts{u};
my $use_keys = $opts{k} || 0;
my $verbose  = $opts{v} || 0;
my $password = '';

unless ($use_keys) {
    if ($opts{p}) {
        $password = $opts{p};
    } else {
        print "Password for $username: ";
        ReadMode('noecho');
        chomp($password = ReadLine(0));
        ReadMode('restore');
        print "\n";
    }
}

my $logfh;
if ($opts{l}) {
    open($logfh, '>>', $opts{l}) or die "Cannot open log $opts{l}: $!";
    $logfh->autoflush(1);
}

my @devices;
if ($opts{h}) {
    push @devices, $opts{h};
} elsif ($opts{f}) {
    open(my $fh, '<', $opts{f}) or die "Cannot open device file $opts{f}: $!";
    while (<$fh>) {
        chomp; s/^\s+|\s+$//g;
        push @devices, $_ if $_ && !/^#/;
    }
    close $fh;
}

sub log_output {
    my $msg = shift;
    print $msg;
    print $logfh $msg if $logfh;
}

sub collect_neighbors {
    my ($host) = @_;
    my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
    log_output("\n" . "=" x 60 . "\n");
    log_output("Device: $host  |  $timestamp\n");
    log_output("=" x 60 . "\n");

    my @ssh_cmd = ('ssh', '-o', 'StrictHostKeyChecking=no',
                          '-o', 'ConnectTimeout=10',
                          '-l', $username);
    push @ssh_cmd, '-o', 'BatchMode=yes' if $use_keys;
    push @ssh_cmd, $host;

    my $exp = Expect->new();
    $exp->log_stdout(0);
    $exp->raw_pty(1);

    unless ($exp->spawn(@ssh_cmd)) {
        log_output("ERROR: Failed to spawn SSH to $host: $!\n");
        return;
    }

    unless ($use_keys) {
        my $matched = $exp->expect($timeout,
            [ qr/[Pp]assword:/           => sub { $exp->send("$password\n"); exp_continue; } ],
            [ qr/yes\/no\)\?/            => sub { $exp->send("yes\n");       exp_continue; } ],
            [ qr/[>#]\s*$/               => sub { } ],
            [ qr/Connection refused/     => sub { log_output("ERROR: Connection refused to $host\n"); } ],
            [ qr/No route to host/       => sub { log_output("ERROR: No route to $host\n"); } ],
            [ 'timeout'                  => sub { log_output("ERROR: Timeout waiting for login prompt on $host\n"); } ],
        );
        unless (defined $matched) {
            log_output("ERROR: Authentication or connection failed for $host\n");
            $exp->soft_close();
            return;
        }
    } else {
        $exp->expect($timeout,
            [ qr/[>#]\s*$/ => sub { } ],
            [ 'timeout'    => sub { log_output("ERROR: Timeout connecting to $host\n"); $exp->soft_close(); return; } ],
        );
    }

    $exp->send("terminal length 0\n");
    $exp->expect($timeout, qr/[>#]\s*$/);

    for my $cmd ('show cdp neighbors detail', 'show lldp neighbors detail') {
        $exp->send("$cmd\n");
        my $result = '';
        $exp->expect($timeout,
            [ qr/[>#]\s*$/ => sub { $result = $exp->before(); } ],
            [ 'timeout'    => sub { log_output("  WARN: Timeout on '$cmd'\n"); } ],
        );
        if ($result) {
            if ($result =~ /Invalid input|% Unknown command/i) {
                log_output("  [$cmd]: not supported on this device\n");
            } elsif ($result =~ /Total cdp entries|Device ID|System Name/i) {
                log_output("--- $cmd ---\n");
                log_output($verbose ? $result : _parse_neighbors($result));
            }
        }
    }

    $exp->send("exit\n");
    $exp->soft_close();
}

sub _parse_neighbors {
    my ($raw) = @_;
    my $out = '';
    for my $entry (split(/(?=Device ID:|System Name:)/i, $raw)) {
        my ($dev)   = ($entry =~ /(?:Device ID|System Name)\s*:\s*(\S+)/i);
        my ($iface) = ($entry =~ /Interface\s*:\s*(\S+)/i);
        my ($port)  = ($entry =~ /(?:Port ID|Port Description)\s*[:(]\s*(\S+)/i);
        my ($plat)  = ($entry =~ /Platform\s*:\s*([^\n,]+)/i);
        my ($ip)    = ($entry =~ /IP address\s*:\s*(\S+)/i);
        next unless $dev;
        $plat =~ s/\s+$// if $plat;
        $out .= sprintf("  Neighbor: %-30s  Local: %-18s  Remote: %-18s",
            $dev, $iface // '?', $port // '?');
        $out .= "  IP: $ip"          if $ip;
        $out .= "  Platform: $plat"  if $plat;
        $out .= "\n";
    }
    return $out || "  (no neighbors found)\n";
}

collect_neighbors($_) for @devices;
log_output("\nDone. " . scalar(@devices) . " device(s) queried.\n");
close $logfh if $logfh;