#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# bgp_peers_v2.pl - Enhanced BGP Peer Analysis with Route Prefix Inspection
# =============================================================================
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers via SSH and performs detailed BGP
#   peer analysis including prefix counts, AS path inspection, dampened routes,
#   and peer uptime/flap detection. Generates a structured report suitable for
#   capacity planning and troubleshooting.
#
# Usage:
#   ./bgp_peers_v2.pl --host <ip> [--hosts-file <file>] [--user <user>]
#                     [--pass <pass>] [--logfile <file>] [--vrf <vrf>]
#                     [--as <asn>] [--help]
#
# Prerequisites:
#   - Net::SSH::Expect (cpan install Net::SSH::Expect)
#   - SSH access to target device(s)
#   - Read-only or operator-level credentials sufficient
#
# Examples:
#   ./bgp_peers_v2.pl --host 192.168.1.1 --user netops --pass s3cr3t
#   ./bgp_peers_v2.pl --hosts-file routers.txt --vrf MGMT --logfile bgp_report.log
# =============================================================================

my ($host, $hosts_file, $user, $pass, $logfile, $vrf, $local_as, $help);
$user    = $ENV{NET_USER} // 'admin';
$pass    = $ENV{NET_PASS} // 'admin';
$logfile = '';
$vrf     = '';

GetOptions(
    'host=s'       => \$host,
    'hosts-file=s' => \$hosts_file,
    'user=s'       => \$user,
    'pass=s'       => \$pass,
    'logfile=s'    => \$logfile,
    'vrf=s'        => \$vrf,
    'as=i'         => \$local_as,
    'help'         => \$help,
) or die "Error parsing options. Use --help for usage.\n";

if ($help) {
    system("grep '^#' $0 | head -30");
    exit 0;
}

die "Provide --host or --hosts-file\n" unless $host || $hosts_file;

my @targets;
push @targets, $host if $host;
if ($hosts_file) {
    open my $fh, '<', $hosts_file or die "Cannot open $hosts_file: $!\n";
    while (<$fh>) { chomp; push @targets, $_ if /\S/ && !/^#/; }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open logfile $logfile: $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);

sub output {
    my $line = shift;
    print $line . "\n";
    print $log_fh $line . "\n" if $log_fh;
}

sub analyze_device {
    my $device = shift;
    output("=" x 70);
    output("Device: $device  |  Time: $timestamp");
    output("=" x 70);

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => 15,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    eval {
        my $login = $ssh->login();
        unless ($login =~ /[>#]/) {
            die "Authentication failed or unexpected prompt on $device\n";
        }
    };
    if ($@) {
        output("  ERROR: $@");
        return;
    }

    $ssh->exec("terminal length 0");
    $ssh->exec("terminal width 0");

    my $sum_cmd = $vrf
        ? "show bgp vpnv4 unicast vrf $vrf summary"
        : "show bgp ipv4 unicast summary";

    my $summary = $ssh->exec($sum_cmd);
    unless ($summary) {
        output("  ERROR: No response to BGP summary command.");
        $ssh->close();
        return;
    }

    my ($router_id, $local_asn, $table_ver, $total_paths);
    if ($summary =~ /BGP router identifier ([\d.]+), local AS number (\d+)/) {
        ($router_id, $local_asn) = ($1, $2);
    }
    if ($summary =~ /RIB entries (\d+).*?using.*?paths (\d+)/s) {
        ($table_ver, $total_paths) = ($1, $2);
    }

    output("  Router ID : " . ($router_id  // 'unknown'));
    output("  Local AS  : " . ($local_asn  // 'unknown'));
    output("  RIB Paths : " . ($total_paths // 'unknown'));
    output("");
    output(sprintf("  %-20s %-7s %-7s %-10s %-10s %-12s %s",
        "Neighbor", "AS", "State", "Up/Down", "PfxRcvd", "PfxSent", "Desc"));
    output("  " . "-" x 80);

    my @peers_down;
    for my $line (split /\n/, $summary) {
        next unless $line =~ /^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)?$/;
        my ($neighbor, $version, $remote_as, $msg_rcvd, $msg_sent, $tbl_ver,
            $in_q, $out_q, $updown, $state_pfx) = split /\s+/, $line;

        next unless $neighbor =~ /^\d+\.\d+\.\d+\.\d+$/;
        my @fields   = split /\s+/, $line;
        $neighbor    = $fields[0];
        my $as       = $fields[2] // '?';
        $updown      = $fields[8] // '?';
        $state_pfx   = $fields[9] // '?';
        my $desc     = join(' ', @fields[10..$#fields]) // '';

        my $pfx_sent = '?';
        if ($state_pfx =~ /^\d+$/) {
            my $detail = $ssh->exec("show bgp ipv4 unicast neighbors $neighbor | include prefixes");
            if ($detail =~ /(\d+) prefixes advertised/) { $pfx_sent = $1; }
        }

        output(sprintf("  %-20s %-7s %-7s %-10s %-10s %-12s %s",
            $neighbor, $as, '', $updown, $state_pfx, $pfx_sent, $desc));

        push @peers_down, $neighbor
            if $state_pfx =~ /^(Idle|Active|Connect|OpenSent|OpenConfirm)$/i;
    }

    if (@peers_down) {
        output("");
        output("  *** PEERS NOT ESTABLISHED: " . join(', ', @peers_down));
    }

    my $damp = $ssh->exec("show bgp ipv4 unicast dampened-paths");
    my $damp_count = () = $damp =~ /^\s*[\d.]+\s+d/mg;
    if ($damp_count > 0) {
        output("");
        output("  WARNING: $damp_count dampened prefix(es) detected.");
    }

    $ssh->close();
    output("");
}

for my $device (@targets) {
    analyze_device($device);
}

close $log_fh if $log_fh;