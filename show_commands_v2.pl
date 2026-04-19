#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# spanning_tree_audit.pl - Cisco IOS Spanning Tree Status Collector
#
# Purpose:
#   Connects to one or more Cisco IOS devices via SSH and collects spanning
#   tree topology information including root bridge status, port roles/states,
#   and topology change counters. Useful for verifying STP stability and
#   identifying potential loop conditions or misconfigured priorities.
#
# Usage:
#   ./spanning_tree_audit.pl -h <host>          (single device)
#   ./spanning_tree_audit.pl -f <hosts_file>    (one IP/hostname per line)
#   ./spanning_tree_audit.pl -h <host> -l       (enable log file output)
#   ./spanning_tree_audit.pl -h <host> -u admin -p secret
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to target devices (privilege 1 sufficient for show commands)
#
# Output:
#   Per-VLAN STP summary: root bridge, local role, port states, TC count
# =============================================================================

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log, $opt_timeout);
$opt_user    = $ENV{NET_USER} // 'admin';
$opt_pass    = $ENV{NET_PASS} // '';
$opt_timeout = 20;

GetOptions(
    'h|host=s'    => \$opt_host,
    'f|file=s'    => \$opt_file,
    'u|user=s'    => \$opt_user,
    'p|pass=s'    => \$opt_pass,
    'l|log'       => \$opt_log,
    't|timeout=i' => \$opt_timeout,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l] [-t sec]\n";

die "Specify -h <host> or -f <file>\n" unless $opt_host || $opt_file;
die "Password required (-p or NET_PASS env)\n" unless $opt_pass;

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open my $fh, '<', $opt_file or die "Cannot open $opt_file: $!\n";
    while (<$fh>) {
        chomp;
        s/#.*//;
        s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
}

my $log_fh;
if ($opt_log) {
    my $ts   = strftime('%Y%m%d_%H%M%S', localtime);
    my $name = "stp_audit_${ts}.log";
    open $log_fh, '>', $name or warn "Cannot open log $name: $!\n";
}

sub out {
    print @_;
    print $log_fh @_ if $log_fh;
}

sub audit_device {
    my ($host) = @_;
    out("\n" . "=" x 60 . "\n");
    out("Host: $host  [" . strftime('%Y-%m-%d %H:%M:%S', localtime) . "]\n");
    out("=" x 60 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $opt_user,
        password    => $opt_pass,
        raw_pty     => 1,
        timeout     => $opt_timeout,
    );

    eval {
        my $login = $ssh->login();
        unless ($login =~ /[>#]/) {
            die "Authentication failed or unexpected prompt\n";
        }
    };
    if ($@) {
        out("ERROR: Cannot connect to $host: $@\n");
        return;
    }

    # Disable paging
    $ssh->send('terminal length 0');
    $ssh->waitfor('\s*[>#]', 5);

    # Collect hostname for context
    $ssh->send('show version | include hostname|uptime');
    my $ver = $ssh->waitfor('\s*[>#]', 10) // '';
    if ($ver =~ /(\S+)\s+uptime/) {
        out("Device hostname: $1\n");
    }

    # Get STP summary
    $ssh->send('show spanning-tree summary');
    my $summary = $ssh->waitfor('\s*[>#]', 15) // '';
    out("\n-- STP Summary --\n");
    for my $line (split /\n/, $summary) {
        next if $line =~ /^\s*$|show spanning/;
        out("  $line\n") if $line =~ /Root bridge|Switch is|portfast|BPDU|mode|Total/i;
    }

    # Get per-VLAN detail
    $ssh->send('show spanning-tree detail | include ieee|VLAN|Root ID|Bridge ID|changes|last change|port|Desg|Altn|Back');
    my $detail = $ssh->waitfor('\s*[>#]', 20) // '';
    out("\n-- Per-VLAN Detail --\n");
    my $current_vlan = '';
    for my $line (split /\n/, $detail) {
        next if $line =~ /^\s*$|show spanning/;
        if ($line =~ /(VLAN\d+|MST\d+)/i) {
            $current_vlan = $1;
            out("\n  [$current_vlan]\n");
        }
        if ($line =~ /Root ID|Bridge ID|topology changes|last topology/i) {
            (my $clean = $line) =~ s/^\s+//;
            out("    $clean\n");
        }
    }

    $ssh->send('exit');
    out("\nAudit complete for $host\n");
}

out("Spanning Tree Audit\n");
out("Devices: " . scalar(@devices) . "\n");

for my $dev (@devices) {
    audit_device($dev);
}

close $log_fh if $log_fh;