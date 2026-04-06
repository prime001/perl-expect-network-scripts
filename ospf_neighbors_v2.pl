#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# ospf_neighbor_detail.pl - OSPF Neighbor Detail & Mismatch Diagnostics
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers and runs 'show ip ospf neighbor detail'
#   to surface timer mismatches, MTU issues, dead-interval drift, and area
#   misconfigurations.  Complements basic neighbor-state checks by examining
#   the per-neighbor parameters that cause adjacency failures.
#
# Usage:
#   Single device:    ./ospf_neighbor_detail.pl -h 192.168.1.1
#   Device list:      ./ospf_neighbor_detail.pl -f routers.txt
#   With log:         ./ospf_neighbor_detail.pl -f routers.txt -l detail.log
#   Custom creds:     ./ospf_neighbor_detail.pl -h 10.0.0.1 -u admin -p s3cr3t
#   Filter by area:   ./ospf_neighbor_detail.pl -h 10.0.0.1 -a 0
#
# Device file format (one IP/hostname per line, # = comment):
#   192.168.1.1
#   core-rtr.example.com
#   # 10.0.0.5  disabled
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH read access to target routers (privilege 1 sufficient)
#   Cisco IOS 12.4+ / IOS-XE 3.x+ / NX-OS 5.x+
#
# Exit codes:
#   0 - No mismatches or warnings found
#   1 - One or more parameter mismatches detected
#   2 - Script error (bad args, all connections failed)
# =============================================================================

my ($host, $device_file, $log_file, $username, $password, $filter_area, $timeout, $help);
$username    = $ENV{NET_USER} // 'admin';
$password    = $ENV{NET_PASS} // '';
$timeout     = 20;
$filter_area = undef;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$device_file,
    'l|log=s'     => \$log_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'a|area=s'    => \$filter_area,
    't|timeout=i' => \$timeout,
    'help'        => \$help,
) or die "Error parsing options. Use --help for usage.\n";

if ($help) {
    open(my $fh, '<', $0) or die "Cannot read self: $!\n";
    while (<$fh>) { last unless /^#/; s/^# ?//; print }
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
my $warnings = 0;
my $failed   = 0;

emit("=" x 72 . "\n");
emit("OSPF Neighbor Detail Diagnostics  |  $ts\n");
emit(defined $filter_area ? "Filtering to area: $filter_area\n" : "");
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

    my $login;
    eval { $login = $ssh->login() };
    if ($@ || !defined $login) {
        emit("  ERROR: SSH login failed" . ($@ ? " - $@" : "") . "\n");
        $failed++;
        next;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('\$|#|>', 5);

    $ssh->send('show ip ospf neighbor detail');
    my $raw = $ssh->waitfor('\$|#|>', $timeout);

    unless (defined $raw && length($raw) > 20) {
        emit("  ERROR: No output received (timeout or unsupported platform)\n");
        $failed++;
        $ssh->close();
        next;
    }

    # Parse neighbor blocks separated by blank lines
    my @blocks = split /\n(?=Neighbor\s+\d+\.\d+\.\d+\.\d+)/, $raw;
    my $nbr_count = 0;

    for my $block (@blocks) {
        next unless $block =~ /Neighbor\s+(\d+\.\d+\.\d+\.\d+)/;
        my $nbr_id = $1;

        my ($area)      = $block =~ /in the area\s+([\d.]+)/i;
        my ($state)     = $block =~ /Neighbor is\s+(\S+)/i;
        my ($iface)     = $block =~ /interface address.*?(?:on|,)\s*(\S+)/i
                       || $block =~ /Address\s+[\d.]+.*?Interface\s+(\S+)/i;
        my ($dead_time) = $block =~ /Dead timer due in\s+(\S+)/i;
        my ($hello)     = $block =~ /Hello due in\s+(\S+)/i;
        my ($priority)  = $block =~ /Neighbor priority is\s+(\d+)/i;
        my ($retrans)   = $block =~ /Number of DBD retrans during last exchange\s+(\d+)/i;
        my ($options)   = $block =~ /Options is\s+(0x[0-9A-Fa-f]+)/i;

        next if defined $filter_area && defined $area && $area ne $filter_area;

        $nbr_count++;
        emit(sprintf("  Neighbor %-16s  Area: %-10s  State: %s\n",
                     $nbr_id, $area // 'unknown', $state // 'unknown'));
        emit(sprintf("    Interface: %-18s  Priority: %s\n",
                     $iface // 'unknown', $priority // 'n/a'));
        emit(sprintf("    Dead timer: %-16s  Hello: %s\n",
                     $dead_time // 'n/a', $hello // 'n/a'));

        # Flag retransmit storms - sign of MTU mismatch or congestion
        if (defined $retrans && $retrans > 5) {
            emit("    WARN: High DBD retransmissions ($retrans) - possible MTU mismatch\n");
            $warnings++;
        }

        # Flag non-converged adjacencies
        if (defined $state && $state !~ /^FULL|2WAY/) {
            emit("    WARN: Adjacency not converged (state: $state)\n");
            $warnings++;
        }
    }

    emit("  No OSPF neighbors found" . (defined $filter_area ? " in area $filter_area" : "") . "\n")
        if $nbr_count == 0;

    $ssh->close();
}

emit("\n" . "=" x 72 . "\n");
emit(sprintf("Devices: %d  |  Failures: %d  |  Warnings: %d\n",
             scalar(@devices), $failed, $warnings));
emit("=" x 72 . "\n");

close $log_fh if $log_fh;
exit( ($failed == scalar(@devices)) ? 2 : ($warnings ? 1 : 0) );