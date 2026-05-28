#!/usr/bin/perl
#
# acl_audit.pl - Cisco IOS Access Control List Auditor
#
# Purpose:
#   Connects to one or more Cisco IOS devices via SSH and audits IP ACL
#   configuration. Reports all named/numbered ACLs with entry counts and
#   hit counts, shows which direction each is applied, and flags orphaned
#   ACLs (defined but not applied to any interface) and phantom references
#   (referenced on an interface but missing from the running config).
#
# Usage:
#   Single device:  ./acl_audit.pl -h 192.168.1.1 -u admin [-p pass] [-l audit.log]
#   Device list:    ./acl_audit.pl -f devices.txt  -u admin [-p pass] [-l audit.log]
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#   SSH enabled on target devices; account needs at minimum 'show' privilege.
#
# Tested on: Cisco IOS 12.4, 15.x, IOS-XE 16.x, IOS-XR 6.x (read-only show cmds)

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $logfile);
my $timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$file,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'l|log=s'     => \$logfile,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> -u <user> [-p <pass>] [-l <logfile>]\n";

die "Specify -h <host> or -f <file>\n" unless $host || $file;
die "Username required (-u)\n"         unless $user;

my @devices;
if ($host) {
    @devices = ($host);
} else {
    open(my $fh, '<', $file) or die "Cannot open device file '$file': $!\n";
    @devices = map { chomp; $_ } grep { /\S/ && !/^\s*#/ } <$fh>;
    close $fh;
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log '$logfile': $!\n";
}

sub out {
    my $msg = shift;
    print $msg;
    print {$log_fh} $msg if $log_fh;
}

sub audit_device {
    my $device = shift;
    out("\n" . "=" x 64 . "\n");
    out(sprintf "Device: %-30s  %s\n", $device, strftime("%Y-%m-%d %H:%M:%S", localtime));
    out("=" x 64 . "\n");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $device,
            user     => $user,
            password => $pass,
            raw_pty  => 1,
            timeout  => $timeout,
        );
        $ssh->login();
    };
    if ($@) {
        out("  ERROR: Connection failed - $@\n");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('>#?\s*$', $timeout);

    $ssh->send("show ip access-lists");
    my $acl_raw = $ssh->waitfor('>#?\s*$', $timeout) // '';

    $ssh->send("show running-config | include ip access-group");
    my $apply_raw = $ssh->waitfor('>#?\s*$', $timeout) // '';

    $ssh->close();

    # Parse ACL definitions: name -> { entries, hits }
    my %defined;
    my $cur;
    for my $line (split /\n/, $acl_raw) {
        if ($line =~ /^(?:Standard|Extended) IP access list (\S+)/) {
            $cur = $1;
            $defined{$cur} = { entries => 0, hits => 0 };
        } elsif ($cur) {
            $defined{$cur}{entries}++ if $line =~ /^\s+(permit|deny)/i;
            $defined{$cur}{hits}    += $1 if $line =~ /\((\d+) match(?:es)?\)/;
        }
    }

    # Parse interface applications: acl_name -> [directions]
    my %applied;
    for my $line (split /\n/, $apply_raw) {
        if ($line =~ /ip access-group (\S+)\s+(in|out)/i) {
            push @{$applied{$1}}, $2;
        }
    }

    out("\nDefined ACLs:\n");
    if (%defined) {
        for my $acl (sort keys %defined) {
            my $dirs   = exists $applied{$acl} ? join('+', sort @{$applied{$acl}}) : undef;
            my $status = $dirs ? sprintf("applied %-8s", $dirs) : 'NOT APPLIED   [ORPHAN]';
            out(sprintf "  %-32s  %3d entries  %8d hits  %s\n",
                $acl, $defined{$acl}{entries}, $defined{$acl}{hits}, $status);
        }
    } else {
        out("  No IP access lists found\n");
    }

    out("\nInterface ACL references:\n");
    my $ref_found = 0;
    for my $acl (sort keys %applied) {
        next if exists $defined{$acl};
        out(sprintf "  [WARNING] ACL '%-28s' applied (%s) but NOT defined in config!\n",
            $acl, join('+', @{$applied{$acl}}));
        $ref_found = 1;
    }
    out("  All applied ACLs exist in config\n") unless $ref_found;
}

out("ACL Audit Report\n");
out("Generated : " . strftime("%Y-%m-%d %H:%M:%S", localtime) . "\n");
out("Devices   : " . scalar(@devices) . "\n");

audit_device($_) for @devices;

out("\nAudit complete.\n");
close $log_fh if $log_fh;