The task is a direct code generation request with explicit output format instructions ("Output ONLY the script content"). The brainstorming skill doesn't apply here — the spec is fully defined. Writing the script now.

#!/usr/bin/perl
#
# stp_audit.pl - Spanning Tree Protocol Audit Tool
#
# Purpose:
#   SSH into Cisco IOS/IOS-XE switches and audit STP topology. Reports root
#   bridge status per VLAN, blocked port counts, topology change counters,
#   and flags recent topology changes that may indicate network instability.
#
# Usage:
#   stp_audit.pl -h <host> [-u <user>] [-p <pass>] [-l <logfile>]
#   stp_audit.pl -f <hostfile> [-u <user>] [-p <pass>] [-l <logfile>]
#
# Prerequisites:
#   cpan install Net::SSH::Expect Getopt::Long
#
# Examples:
#   stp_audit.pl -h 192.168.1.10 -u netops -p s3cr3t
#   stp_audit.pl -f switches.txt -u netops -l /var/log/stp_audit.log
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $hostfile, $user, $pass, $logfile);
$user = 'admin';

GetOptions(
    'h|host=s' => \$host,
    'f|file=s' => \$hostfile,
    'u|user=s' => \$user,
    'p|pass=s' => \$pass,
    'l|log=s'  => \$logfile,
) or die "Usage: $0 -h <host>|-f <file> [-u user] [-p pass] [-l logfile]\n";

die "Specify -h <host> or -f <file>\n" unless $host || $hostfile;

unless ($pass) {
    print "Password: ";
    system('stty', '-echo');
    chomp($pass = <STDIN>);
    system('stty', 'echo');
    print "\n";
}

my @hosts;
if ($host) {
    @hosts = ($host);
} else {
    open(my $fh, '<', $hostfile) or die "Cannot open $hostfile: $!\n";
    @hosts = map { chomp; $_ } grep { /\S/ && !/^#/ } <$fh>;
    close $fh;
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open $logfile: $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=" x 62 . "\nSTP Audit Report - $ts\n" . "=" x 62 . "\n");

for my $device (@hosts) {
    out("\n[Device: $device]\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $device,
            user     => $user,
            password => $pass,
            raw_pty  => 1,
            timeout  => 15,
        );
    };
    if ($@ || !$ssh) {
        out("  ERROR: Connection failed - $@\n");
        next;
    }

    eval {
        my $login = $ssh->login();
        if ($login !~ /[\$#>]/) {
            die "Login prompt not detected (auth failure?)\n";
        }

        $ssh->send("terminal length 0");
        $ssh->waitfor('[#>]', 5);

        $ssh->send("show spanning-tree summary totals");
        my $summary = $ssh->waitfor('[#>]', 15) // '';

        $ssh->send("show spanning-tree detail");
        my $detail = $ssh->waitfor('[#>]', 25) // '';

        $ssh->send("exit");

        # Parse summary: root bridge counts and blocked ports
        my ($root_vlans, $blocking) = (0, 0);
        for my $line (split /\n/, $summary) {
            $root_vlans++ if $line =~ /\broot\b/i;
            $blocking += $1 if $line =~ /(\d+)\s+blocking/i;
        }
        out("  Root bridge for $root_vlans VLAN(s)\n");
        out("  Blocked ports: $blocking\n");
        out("  WARN: No VLANs where this switch is root\n") if $root_vlans == 0;

        # Parse detail: per-VLAN topology change tracking
        my ($current_vlan, $tc_count);
        for my $line (split /\n/, $detail) {
            if ($line =~ /MST(\d+)|VLAN(\d+)/i) {
                $current_vlan = $1 // $2;
            }
            if ($line =~ /Number of topology changes\s+(\d+)/i) {
                $tc_count = $1;
                if ($tc_count > 50) {
                    out("  WARN: VLAN/MST $current_vlan - $tc_count topology changes (STP instability risk)\n");
                }
            }
            if ($line =~ /last topology change\s+(\d+):(\d+):(\d+)/i) {
                my $age_sec = $1 * 3600 + $2 * 60 + $3;
                if ($age_sec < 1800 && defined $current_vlan) {
                    out("  WARN: VLAN/MST $current_vlan - topology change ${1}h${2}m${3}s ago\n");
                }
            }
        }
        out("  OK: No instability indicators found\n") unless $summary.$detail =~ /WARN/;
    };
    if ($@) {
        out("  ERROR: Session error - $@\n");
    }
}

out("\nAudit complete.\n");
close $log_fh if $log_fh;