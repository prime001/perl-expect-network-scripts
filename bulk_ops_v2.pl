#!/usr/bin/perl
# =============================================================================
# acl_audit.pl - Cisco IOS Access Control List Audit Tool
#
# Purpose:
#   Connects to one or more Cisco IOS devices via SSH and audits ACL
#   configuration: enumerates all named/numbered ACLs, their rule counts,
#   cumulative hit counters, and interface bindings. Flags empty, zero-hit,
#   and unbound ACLs for security review and cleanup.
#
# Usage:
#   Single device:  ./acl_audit.pl -h 192.168.1.1 -u admin [-p pass] [-l out.log]
#   Device file:    ./acl_audit.pl -f devices.txt  -u admin [-p pass] [-l out.log]
#
#   devices.txt: one IP/hostname per line; lines beginning with # are ignored
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   Tested against Cisco IOS 12.4+, IOS-XE 16.x+
#   SSH key auth preferred; -p enables password auth
#
# Output:
#   Per-device table: ACL name, rule count, total hits, binding flags
#   UNUSED  = ACL has rules but zero hits since last counter clear
#   UNBOUND = ACL not referenced by any 'ip access-group' statement
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $logfile);
my $timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$device_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'l|log=s'     => \$logfile,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h HOST|-f FILE -u USER [-p PASS] [-l LOG] [-t SECS]\n";

die "Specify -h HOST or -f FILE\n" unless $host || $device_file;
die "Specify -u USER\n"            unless $username;

my @devices;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*[#]/ || /^\s*$/; push @devices, $_; }
    close $fh;
} else {
    @devices = ($host);
}

my $LOG;
if ($logfile) {
    open($LOG, '>>', $logfile) or die "Cannot open $logfile: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=" x 62);
out("ACL Audit Report  --  $ts");
out("Devices: " . scalar(@devices));
out("=" x 62);

for my $dev (@devices) {
    out("\n[+] $dev");
    audit_device($dev);
}

close $LOG if $LOG;

sub audit_device {
    my ($dev) = @_;
    my $ssh = Net::SSH::Expect->new(
        host     => $dev,
        user     => $username,
        ($password ? (password => $password) : ()),
        raw_pty  => 1,
        timeout  => $timeout,
    );

    eval { my $r = $ssh->login(); die "bad prompt\n" unless $r =~ /[>#]/; };
    if ($@) {
        out("    ERROR: Login failed -- " . ($@ =~ s/\n/ /gr));
        return;
    }

    $ssh->send("terminal length 0\n");  $ssh->waitfor('[>#]', 5);

    $ssh->send("show ip access-lists\n");
    my $acl_out = eval { $ssh->waitfor('[>#]', $timeout) } // '';
    if ($@) { out("    ERROR: Timeout on show ip access-lists"); $ssh->close(); return; }

    $ssh->send("show running-config | include ip access-group\n");
    my $bind_out = eval { $ssh->waitfor('[>#]', $timeout) } // '';

    $ssh->close();
    parse_report($acl_out, $bind_out);
}

sub parse_report {
    my ($acl_text, $bind_text) = @_;
    my (%acls, $cur);

    for my $line (split /\n/, $acl_text) {
        if ($line =~ /^(?:Standard|Extended) IP access list (\S+)/) {
            $cur = $1;
            $acls{$cur} //= { rules => 0, hits => 0 };
        } elsif ($cur) {
            $acls{$cur}{rules}++ if $line =~ /(?:permit|deny)/i;
            $acls{$cur}{hits}   += $1 if $line =~ /(\d+) matches/;
        }
    }

    my %bound;
    $bound{$1} = 1 while $bind_text =~ /ip access-group (\S+)/g;

    if (!%acls) { out("    No ACLs configured."); return; }

    my $fmt = "    %-28s %5s %10s  %s";
    out(sprintf($fmt, 'ACL Name', 'Rules', 'Hits', 'Flags'));
    out("    " . "-" x 54);

    for my $name (sort keys %acls) {
        my @flags;
        push @flags, 'UNUSED'  if $acls{$name}{rules} > 0 && $acls{$name}{hits} == 0;
        push @flags, 'UNBOUND' unless $bound{$name};
        out(sprintf($fmt, $name, $acls{$name}{rules}, $acls{$name}{hits},
            @flags ? join(' ', @flags) : 'ok'));
    }
    out(sprintf("    Summary: %d ACL(s), %d bound to interfaces",
        scalar keys %acls, scalar keys %bound));
}

sub out {
    my ($msg) = @_;
    print "$msg\n";
    print $LOG "$msg\n" if $LOG;
}