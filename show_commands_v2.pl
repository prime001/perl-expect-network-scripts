The repo isn't on this machine — outputting the script content directly:

```
#!/usr/bin/perl
#
# spanning_tree_audit.pl
#
# Purpose:
#   Audits Spanning Tree Protocol (STP) status on Cisco IOS/IOS-XE devices.
#   Reports root bridge ownership per VLAN, port roles/states, topology change
#   counters, and flags ports stuck in LISTENING or LEARNING states that may
#   indicate a reconvergence event or misconfiguration.
#
# Usage:
#   spanning_tree_audit.pl -h <host> [-u <user>] [-p <pass>] [-l <logfile>]
#   spanning_tree_audit.pl -f <device_file> [-u <user>] [-p <pass>] [-l <logfile>]
#
#   Credentials fall back to NET_USER / NET_PASS environment variables.
#   Device file: one IP or hostname per line; lines starting with # are ignored.
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   cpan Getopt::Long
#
# Example:
#   NET_USER=admin NET_PASS=s3cr3t ./spanning_tree_audit.pl -f switches.txt -l stp.log

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $logfile);
my $username = $ENV{NET_USER} // 'admin';
my $password = $ENV{NET_PASS} // '';

GetOptions(
    'h|host=s' => \$host,
    'f|file=s' => \$device_file,
    'u|user=s' => \$username,
    'p|pass=s' => \$password,
    'l|log=s'  => \$logfile,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile]\n";

die "ERROR: Specify -h <host> or -f <device_file>\n" unless $host || $device_file;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*[#\s]/; push @devices, $_; }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open logfile $logfile: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
say_out("=" x 60);
say_out("Spanning Tree Audit  $ts");
say_out("=" x 60);

audit_device($_) for @devices;

close $log_fh if $log_fh;
exit 0;

sub audit_device {
    my ($dev) = @_;
    say_out("\n[+] $dev");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $dev,
            user     => $username,
            password => $password,
            raw_pty  => 1,
            timeout  => 20,
        );
    };
    if ($@ || !$ssh) {
        say_out("    ERROR: SSH init failed — $@");
        return;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        say_out("    ERROR: Authentication failed");
        return;
    }

    $ssh->exec("terminal length 0");

    my $ver = eval { $ssh->exec("show version | include ^hostname") } // '';
    (my $hn = $ver) =~ s/hostname\s+(\S+).*/$1/si;
    $hn =~ s/\s+//g;
    $hn = $dev unless length $hn;
    say_out("    Hostname : $hn");

    my $summary = eval { $ssh->exec("show spanning-tree summary totals") } // '';
    parse_summary($summary);

    my $detail = eval { $ssh->exec("show spanning-tree") } // '';
    parse_detail($detail);

    $ssh->close();
}

sub parse_summary {
    my ($out) = @_;
    for (split /\r?\n/, $out) {
        say_out("    Root VLANs    : $1") if /Root bridge for:\s*(.+)/i;
        say_out("    !WARN Topo Chg: $1 changes") if /(\d+)\s+topology change/i;
        say_out("    PortFast dflt : $1") if /Portfast Default\s+is\s+(\S+)/i;
        say_out("    BPDU Guard    : $1") if /BPDU Guard Default\s+is\s+(\S+)/i;
    }
}

sub parse_detail {
    my ($out) = @_;
    my ($vlan, @flags) = ('');

    for (split /\r?\n/, $out) {
        $vlan = $1 if /^VLAN0*(\d+)/i;
        push @flags, "VLAN $vlan: this device is ROOT" if /This bridge is the root/i;

        # Format: Interface  Role  Sts  Cost  Prio  Type
        if (/^(\S+)\s+\S+\s+(BLK|LIS|LRN)\s+/i) {
            my %label = (BLK => 'BLOCKING', LIS => 'LISTENING', LRN => 'LEARNING');
            push @flags, "VLAN $vlan: $1 in $label{uc $2}";
        }
    }

    if (@flags) {
        say_out("    $_") for @flags;
    } else {
        say_out("    All ports forwarding/designated — no STP anomalies found.");
    }
}

sub say_out {
    my ($line) = @_;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}
```

**What it does and why it's not a duplicate:** This script focuses specifically on STP topology health — root bridge ownership per VLAN, ports stuck in BLK/LIS/LRN states, topology change counters, and PortFast/BPDU Guard global settings. None of the existing v1/v2 scripts touch spanning tree. It's a common pre-change check before any Layer 2 maintenance window.