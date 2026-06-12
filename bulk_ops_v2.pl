#!/usr/bin/perl
# =============================================================================
# acl_audit.pl - Cisco IOS ACL Audit Tool
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and audits access control
#   lists. Flags overly permissive rules (permit ip any any), ACLs missing
#   a deny-log terminator, collects hit counts for optimization review, and
#   produces a per-device summary suitable for security compliance reports.
#
# Usage:
#   acl_audit.pl -h 192.168.1.1
#   acl_audit.pl -f hosts.txt -l
#   acl_audit.pl -h 10.0.0.1 -u netops -p secret -e enablepass -l
#
# Options:
#   -h <host>     Single device IP or hostname
#   -f <file>     File with one device IP/hostname per line (# = comment)
#   -u <user>     SSH username (default: $NET_USER env var or 'admin')
#   -p <pass>     SSH password (default: $NET_PASS env var)
#   -e <pass>     Enable password (default: same as SSH password)
#   -l            Write output to acl_audit_TIMESTAMP.log in addition to STDOUT
#   -t <secs>     Per-command timeout in seconds (default: 30)
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   Devices must have SSH enabled; account needs at minimum 'show' privilege.
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_enable, $opt_log);
my $opt_timeout = 30;

GetOptions(
    'h|host=s'    => \$opt_host,
    'f|file=s'    => \$opt_file,
    'u|user=s'    => \$opt_user,
    'p|pass=s'    => \$opt_pass,
    'e|enable=s'  => \$opt_enable,
    'l|log'       => \$opt_log,
    't|timeout=i' => \$opt_timeout,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-e enable] [-l] [-t secs]\n";

die "ERROR: Specify -h <host> or -f <file>\n" unless $opt_host || $opt_file;

$opt_user   //= $ENV{NET_USER} // 'admin';
$opt_pass   //= $ENV{NET_PASS} // die "ERROR: Set -p <pass> or NET_PASS env var\n";
$opt_enable //= $ENV{NET_ENABLE} // $opt_pass;

my @devices;
if ($opt_file) {
    open my $fh, '<', $opt_file or die "ERROR: Cannot open $opt_file: $!\n";
    while (<$fh>) { chomp; s/#.*//; push @devices, $_ if /\S/; }
    close $fh;
} else {
    @devices = ($opt_host);
}

my $logfh;
if ($opt_log) {
    my $logfile = 'acl_audit_' . strftime('%Y%m%d_%H%M%S', localtime) . '.log';
    open $logfh, '>', $logfile or die "ERROR: Cannot open $logfile: $!\n";
    print "Logging output to: $logfile\n";
}

sub emit { print @_; print $logfh @_ if $logfh; }

sub audit_device {
    my ($dev) = @_;
    my $ssh;

    eval {
        $ssh = Net::SSH::Expect->new(
            host       => $dev,
            user       => $opt_user,
            password   => $opt_pass,
            raw_pty    => 1,
            timeout    => $opt_timeout,
            ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=no',
        );
        $ssh->login();
    };
    if ($@) {
        emit "[$dev] FAIL: Connection or authentication error -- $@\n";
        return;
    }

    eval {
        $ssh->send('enable');
        my $r = $ssh->waitfor('assword:|#', $opt_timeout);
        if ($r =~ /assword:/i) {
            $ssh->send($opt_enable);
            $ssh->waitfor('#', $opt_timeout);
        }
        $ssh->send('terminal length 0');
        $ssh->waitfor('#', $opt_timeout);
    };
    if ($@) {
        emit "[$dev] FAIL: Could not enter enable mode\n";
        return;
    }

    $ssh->send('show ip access-lists');
    my $acl_output = $ssh->waitfor('#', $opt_timeout * 2);

    $ssh->send('show version | include uptime');
    my $ver_output = $ssh->waitfor('#', $opt_timeout);
    $ssh->send('exit');

    my ($uptime) = ($ver_output =~ /uptime is (.+)/i);
    $uptime //= 'unknown';

    my (%acls, $cur, @warnings);
    for my $line (split /\r?\n/, $acl_output) {
        if ($line =~ /^(?:Extended|Standard)\s+IP\s+access\s+list\s+(\S+)/i) {
            $cur = $1;
            $acls{$cur} = { entries => 0, hits => 0, permit_any => 0, deny_log => 0 };
        } elsif ($cur && $line =~ /^\s+\d+\s+(.+?)\s*(?:\((\d+)\s+match)?/) {
            my ($rule, $hits) = ($1, $2 // 0);
            $acls{$cur}{entries}++;
            $acls{$cur}{hits} += $hits;
            if ($rule =~ /permit\s+ip\s+any\s+any/i) {
                $acls{$cur}{permit_any} = 1;
                push @warnings, "WARN  [$cur] permit ip any any detected (overly permissive)";
            }
            $acls{$cur}{deny_log} = 1 if $rule =~ /deny\s+any.*\blog\b/i;
        }
    }

    emit "\n" . "=" x 62 . "\n";
    emit sprintf("Device  : %s\n", $dev);
    emit sprintf("Uptime  : %s\n", $uptime);
    emit sprintf("ACLs    : %d\n", scalar keys %acls);
    emit "-" x 62 . "\n";
    emit sprintf("%-28s %7s %11s %10s %8s\n", 'ACL Name', 'Entries', 'Hits', 'PermitAny', 'DenyLog');
    emit "-" x 62 . "\n";

    for my $name (sort keys %acls) {
        my $a = $acls{$name};
        emit sprintf("%-28s %7d %11d %10s %8s\n",
            $name, $a->{entries}, $a->{hits},
            $a->{permit_any} ? 'YES(!)' : 'no',
            $a->{deny_log}   ? 'yes'    : 'NO(!)',
        );
    }

    if (@warnings) {
        emit "\n";
        emit "  $_\n" for @warnings;
    }
}

my $start = strftime('%Y-%m-%d %H:%M:%S', localtime);
emit "ACL Audit  : $start\n";
emit "Devices    : " . scalar(@devices) . "\n";

audit_device($_) for @devices;

emit "\n" . "=" x 62 . "\n";
emit "Audit complete: " . strftime('%Y-%m-%d %H:%M:%S', localtime) . "\n";
close $logfh if $logfh;