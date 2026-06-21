#!/usr/bin/perl
# =============================================================================
# cdp_lldp_neighbors.pl -- CDP/LLDP Neighbor Discovery for Cisco IOS/IOS-XE
# =============================================================================
# Purpose:
#   Connects to one or more Cisco devices via SSH, collects CDP or LLDP
#   neighbor detail output, and presents a structured summary of adjacent
#   devices: device ID, management IP, platform, local/remote port mappings,
#   and capabilities. Used for topology verification, documentation audits,
#   and post-change validation.
#
# Usage:
#   Single device:  ./cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./cdp_lldp_neighbors.pl -f devices.txt -u admin -p secret
#   Log to file:    ./cdp_lldp_neighbors.pl -h 10.0.0.1 -u admin -p secret -l out.log
#   LLDP mode:      ./cdp_lldp_neighbors.pl -h 10.0.0.1 -u admin -p secret --lldp
#
# Prerequisites:
#   Perl modules: Net::SSH::Expect, Getopt::Long
#   Install:      cpanm Net::SSH::Expect
#   Device:       CDP or LLDP enabled; SSH access with exec privilege
#
# Device file format (space-separated, one per line):
#   ip_or_hostname [username] [password]
#   Username and password fall back to -u/-p defaults if omitted.
#   Lines beginning with # are ignored.
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($opt_host, $opt_user, $opt_pass, $opt_file, $opt_log, $opt_lldp);
my $opt_timeout = 30;

GetOptions(
    'h|host=s'    => \$opt_host,
    'u|user=s'    => \$opt_user,
    'p|pass=s'    => \$opt_pass,
    'f|file=s'    => \$opt_file,
    'l|log=s'     => \$opt_log,
    't|timeout=i' => \$opt_timeout,
    'lldp'        => \$opt_lldp,
) or die "Usage: $0 -h HOST -u USER -p PASS [-f FILE] [-l LOG] [--lldp]\n";

die "ERROR: Specify -h HOST or -f FILE\n"  unless $opt_host || $opt_file;
die "ERROR: Username (-u) required\n"      unless $opt_user;
die "ERROR: Password (-p) required\n"      unless $opt_pass;

my $LOG_FH;
if ($opt_log) {
    open($LOG_FH, '>>', $opt_log) or die "Cannot open log '$opt_log': $!\n";
}

sub emit {
    my ($msg) = @_;
    print STDOUT $msg;
    print $LOG_FH $msg if $LOG_FH;
}

sub audit_device {
    my ($host, $user, $pass) = @_;
    my $proto = $opt_lldp ? 'LLDP' : 'CDP';
    my $cmd   = $opt_lldp ? 'show lldp neighbors detail' : 'show cdp neighbors detail';

    emit("\n" . ("=" x 72) . "\n");
    emit(sprintf("Host   : %s\n", $host));
    emit(sprintf("Proto  : %s\n", $proto));
    emit(sprintf("Time   : %s\n", strftime('%Y-%m-%d %H:%M:%S', localtime)));
    emit(("=" x 72) . "\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $user,
        password => $pass,
        raw_pty  => 1,
        timeout  => $opt_timeout,
    );

    my $login;
    eval { $login = $ssh->login() };
    if ($@ || ($login && $login =~ /Permission denied|Authentication failed/i)) {
        emit("ERROR: Authentication failed for $host\n");
        return 0;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('\$|\#|>', 5);
    $ssh->send($cmd);
    my $raw = $ssh->waitfor('\$|\#|>', $opt_timeout);
    eval { $ssh->send('exit'); $ssh->close() };

    unless ($raw) {
        emit("ERROR: No output received from $host\n");
        return 0;
    }

    _parse_and_print($host, $raw, $proto);
    return 1;
}

sub _parse_and_print {
    my ($host, $raw, $proto) = @_;
    my (@neighbors, %cur);

    for my $line (split /\n/, $raw) {
        if ($proto eq 'CDP') {
            if    ($line =~ /^Device ID:\s*(\S+)/i)                              { push @neighbors, {%cur} if %cur; %cur = (device => $1) }
            elsif ($line =~ /IP\s+address:\s*(\d+\.\d+\.\d+\.\d+)/i)            { $cur{ip}     //= $1 }
            elsif ($line =~ /Platform:\s*([^,]+)/i)                              { $cur{platform} = $1 }
            elsif ($line =~ /Interface:\s*(\S+),\s*Port ID[^:]*:\s*(\S+)/i)     { $cur{local} = $1; $cur{remote} = $2 }
            elsif ($line =~ /Capabilities:\s*(.+)/i)                             { $cur{caps}  = $1 }
        } else {
            if    ($line =~ /System Name:\s*(\S+)/i)                             { push @neighbors, {%cur} if %cur; %cur = (device => $1) }
            elsif ($line =~ /Management Addr(?:ess)?.*?(\d+\.\d+\.\d+\.\d+)/i)  { $cur{ip}     //= $1 }
            elsif ($line =~ /System Description:\s*(.+)/i)                       { $cur{platform} = $1 }
            elsif ($line =~ /Local Intf(?:ace)?:\s*(\S+)/i)                      { $cur{local}  = $1 }
            elsif ($line =~ /Port id:\s*(\S+)/i)                                 { $cur{remote} = $1 }
            elsif ($line =~ /System Capabilit(?:ies|y):\s*(.+)/i)               { $cur{caps}   = $1 }
        }
    }
    push @neighbors, {%cur} if %cur && $cur{device};

    if (!@neighbors) {
        emit("No $proto neighbors found on $host\n");
        return;
    }

    my $fmt = "%-32s %-16s %-22s %-18s %-18s\n";
    emit(sprintf($fmt, 'NEIGHBOR DEVICE ID', 'MGMT IP', 'PLATFORM', 'LOCAL PORT', 'REMOTE PORT'));
    emit(("-" x 108) . "\n");
    for my $n (@neighbors) {
        emit(sprintf($fmt,
            substr($n->{device}   // '(unknown)', 0, 31),
            substr($n->{ip}       // 'n/a',       0, 15),
            substr($n->{platform} // 'n/a',       0, 21),
            substr($n->{local}    // 'n/a',       0, 17),
            substr($n->{remote}   // 'n/a',       0, 17),
        ));
    }
    emit(sprintf("\n%s neighbor count: %d\n", $proto, scalar @neighbors));
}

# ---- Main ----
my @targets;
if ($opt_file) {
    open(my $fh, '<', $opt_file) or die "Cannot open '$opt_file': $!\n";
    while (<$fh>) {
        chomp; next if /^\s*#/ || /^\s*$/;
        my ($h, $u, $p) = split /\s+/;
        push @targets, [$h, $u // $opt_user, $p // $opt_pass];
    }
    close $fh;
} else {
    push @targets, [$opt_host, $opt_user, $opt_pass];
}

die "ERROR: No devices to process\n" unless @targets;

my ($ok, $fail) = (0, 0);
for my $t (@targets) {
    audit_device(@$t) ? $ok++ : $fail++;
}

emit(sprintf("\nDone. %d succeeded, %d failed.\n", $ok, $fail));
close($LOG_FH) if $LOG_FH;
exit($fail ? 1 : 0);