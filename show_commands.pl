#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# bgp-summary.pl - BGP Session State Collector
#
# Purpose:
#   Connects to one or more routers via SSH and collects BGP peer summary
#   data. Flags sessions that are not Established, reports uptime and prefix
#   counts. Suited for post-change validation, NOC dashboards, or scheduled
#   health checks across a multi-router BGP estate.
#
# Usage:
#   Single device:    ./bgp-summary.pl -h 192.168.1.1
#   Multiple devices: ./bgp-summary.pl -f routers.txt
#   With log file:    ./bgp-summary.pl -f routers.txt -l bgp_check.log
#   Custom creds:     ./bgp-summary.pl -h 10.0.0.1 -u netops -p s3cret
#   VRF aware:        ./bgp-summary.pl -h 10.0.0.1 -v MGMT
#
# Device file format (one IP or hostname per line, # for comments):
#   10.0.0.1
#   rtr-core-02.example.net
#   # 10.0.0.99  (disabled)
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access with at least read-only privilege (Cisco IOS/IOS-XE/NX-OS)
#   BGP process configured on target devices
#
# Environment variables (avoid passing creds on command line):
#   NET_USER  SSH username  (default: admin)
#   NET_PASS  SSH password
#
# Exit codes:
#   0 - All BGP sessions Established
#   1 - One or more sessions down or in non-Established state
#   2 - Script/connectivity error (no devices reached)
# =============================================================================

my ($host, $device_file, $log_file, $username, $password, $vrf, $timeout, $help);
$username = $ENV{NET_USER} // 'admin';
$password = $ENV{NET_PASS} // '';
$timeout  = 20;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$device_file,
    'l|log=s'     => \$log_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'v|vrf=s'     => \$vrf,
    't|timeout=i' => \$timeout,
    'help'        => \$help,
) or die "Error parsing options. Use --help for usage.\n";

if ($help) {
    open(my $fh, '<', $0) or die "Cannot read $0: $!\n";
    while (<$fh>) { last unless /^#/; s/^#\s?//; print }
    close $fh;
    exit 0;
}

die "Error: specify -h <host> or -f <device_file>\n" unless $host || $device_file;

unless ($password) {
    print "Password for $username: ";
    system('stty -echo');
    chomp($password = <STDIN>);
    system('stty echo');
    print "\n";
}

my @devices;
push @devices, $host if $host;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*[#]/ || /^\s*$/; push @devices, $_ }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

sub emit {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts       = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $down     = 0;
my $failed   = 0;
my $cmd      = $vrf ? "show bgp vrf $vrf summary" : 'show bgp ipv4 unicast summary';

emit("=" x 72 . "\n");
emit("BGP Session Check  |  $ts" . ($vrf ? "  |  VRF: $vrf" : '') . "\n");
emit("=" x 72 . "\n");

for my $device (@devices) {
    emit("\n[ $device ]\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $username,
        password => $password,
        raw_pty  => 1,
        timeout  => $timeout,
    );

    eval { $ssh->login() };
    if ($@) {
        emit("  ERROR: SSH login failed - $@\n");
        $failed++;
        next;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('[#>$]', 5);

    $ssh->send($cmd);
    my $output = $ssh->waitfor('[#>$]', $timeout);

    unless (defined $output && length $output > 20) {
        emit("  ERROR: No output received (timeout or unsupported platform)\n");
        $failed++;
        $ssh->close();
        next;
    }

    my ($router_id, $local_as, $total, @issues);

    for my $line (split /\n/, $output) {
        # Header: "BGP router identifier 1.2.3.4, local AS number 65001"
        if ($line =~ /router identifier\s+([\d.]+).*?AS number\s+(\d+)/i) {
            ($router_id, $local_as) = ($1, $2);
            emit(sprintf("  Router-ID: %-16s  Local AS: %s\n", $router_id, $local_as));
        }
        # Peer line: neighbor, V, AS, MsgRcvd, MsgSent, TblVer, InQ, OutQ, Up/Down, State/PfxRcd
        if ($line =~ /^([\d.a-fA-F:]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)/) {
            my ($peer, $ver, $as, $rcvd, $sent, $updown, $state) = ($1,$2,$3,$4,$5,$6,$7);
            $total++;
            my $established = ($state =~ /^\d+$/);  # prefix count = Established
            my $label = $established ? '  UP' : 'DOWN';
            emit(sprintf("  %-4s  %-18s  AS:%-8s  Up/Down:%-12s  State/Pfx: %s\n",
                         $label, $peer, $as, $updown, $state));
            push @issues, "$peer (AS$as state=$state)" unless $established;
        }
    }

    if (!defined $total) {
        emit("  WARN: No BGP peers parsed - check platform output format\n");
        $down++;
    } elsif (@issues) {
        emit("  SUMMARY: $total peer(s), " . scalar(@issues) . " not Established: "
             . join(', ', @issues) . "\n");
        $down++;
    } else {
        emit("  SUMMARY: $total peer(s), all Established\n");
    }

    $ssh->close();
}

emit("\n" . "=" x 72 . "\n");
emit("Devices checked: " . scalar(@devices)
     . "  |  Failed connections: $failed"
     . "  |  Devices with down peers: $down\n");
emit("=" x 72 . "\n");

close $log_fh if $log_fh;

exit( ($failed == scalar(@devices)) ? 2 : ($down ? 1 : 0) );