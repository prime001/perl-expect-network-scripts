#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# bgp_prefix_audit.pl - BGP Prefix Filter and Policy Audit
#
# PURPOSE:
#   Audits BGP neighbor prefix-lists and route-maps on Cisco IOS/IOS-XE routers.
#   Identifies neighbors missing inbound prefix filters (security risk), shows
#   current prefix counts, and validates policy is applied consistently.
#
# USAGE:
#   ./bgp_prefix_audit.pl --host <ip> --user <username> [--pass <password>]
#                         [--log <logfile>] [--hosts-file <file>]
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   SSH access to device with 'show' privilege level
#
# OUTPUT:
#   Per-neighbor summary: state, prefix-list/route-map applied, prefix count
#   Flags peers with no inbound filtering as [UNFILTERED]

my ($host, $user, $pass, $logfile, $hosts_file, $timeout);
$timeout = 30;

GetOptions(
    'host=s'       => \$host,
    'user=s'       => \$user,
    'pass=s'       => \$pass,
    'log=s'        => \$logfile,
    'hosts-file=s' => \$hosts_file,
    'timeout=i'    => \$timeout,
) or die "Usage: $0 --host <ip> --user <user> [--pass <pass>] [--log <file>]\n";

die "Provide --host or --hosts-file\n" unless $host || $hosts_file;
die "Provide --user\n" unless $user;

$pass //= $ENV{NET_SSH_PASS} // do {
    system("stty -echo");
    print "Password: ";
    chomp($pass = <STDIN>);
    system("stty echo");
    print "\n";
    $pass;
};

my @hosts = $host ? ($host) : do {
    open my $fh, '<', $hosts_file or die "Cannot open $hosts_file: $!";
    grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
};

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!";
}

sub out {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my ($device) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    out("\n=== BGP Prefix Policy Audit: $device [$ts] ===\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        out("ERROR: Connection failed to $device: $@\n");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$\s*#', 5);

    $ssh->send("show ip bgp summary");
    my $summary = $ssh->waitfor('\$\s*#', $timeout);

    my %peers;
    while ($summary =~ /^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\d+)/mg) {
        my ($peer, $updown, $pfx_count) = ($1, $2, $3);
        $peers{$peer} = { state => ($updown =~ /^\d/ ? 'Established' : $updown), prefixes => $pfx_count };
    }

    if (!%peers) {
        out("  No BGP peers found or BGP not configured\n");
        $ssh->close();
        return;
    }

    $ssh->send("show ip bgp neighbors");
    my $nbr_output = $ssh->waitfor('\$\s*#', $timeout);

    my %policy;
    my $current_peer = '';
    for my $line (split /\n/, $nbr_output) {
        if ($line =~ /BGP neighbor is (\d+\.\d+\.\d+\.\d+)/) {
            $current_peer = $1;
            $policy{$current_peer} //= { in_plist => '', out_plist => '', in_rmap => '', out_rmap => '' };
        }
        next unless $current_peer;
        if ($line =~ /Inbound path policy configured is (.+)/)  { $policy{$current_peer}{in_rmap}  = $1 }
        if ($line =~ /Outbound path policy configured is (.+)/) { $policy{$current_peer}{out_rmap} = $1 }
        if ($line =~ /Incoming update prefix filter list is (.+)/) { $policy{$current_peer}{in_plist}  = $1 }
        if ($line =~ /Outgoing update prefix filter list is (.+)/) { $policy{$current_peer}{out_plist} = $1 }
    }

    my ($filtered, $unfiltered) = (0, 0);
    out(sprintf "  %-18s %-13s %-8s %-22s %-22s\n",
        "Neighbor", "State", "Prefixes", "Inbound Filter", "Outbound Filter");
    out("  " . "-" x 87 . "\n");

    for my $peer (sort keys %peers) {
        my $state    = $peers{$peer}{state};
        my $pfx      = $peers{$peer}{prefixes} // '?';
        my $p        = $policy{$peer} // {};
        my $in_filt  = $p->{in_plist}  || $p->{in_rmap}  || '';
        my $out_filt = $p->{out_plist} || $p->{out_rmap} || '';
        my $flag     = (!$in_filt && $state eq 'Established') ? ' [UNFILTERED]' : '';
        $flag ? $unfiltered++ : $filtered++;
        out(sprintf "  %-18s %-13s %-8s %-22s %-22s%s\n",
            $peer, $state, $pfx,
            ($in_filt  || '(none)'),
            ($out_filt || '(none)'),
            $flag);
    }

    my $total = scalar keys %peers;
    out("\n  Summary: $total peers | $unfiltered unfiltered (inbound) | $filtered filtered\n");
    out("  WARNING: $unfiltered peer(s) have no inbound prefix filter!\n") if $unfiltered;

    $ssh->close();
}

audit_device($_) for @hosts;
out("\nDone.\n");
close $log_fh if $log_fh;