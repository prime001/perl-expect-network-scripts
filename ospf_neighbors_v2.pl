```perl
#!/usr/bin/perl
# =============================================================================
# ospf_neighbor_detail.pl - OSPF Neighbor Detail Collector with State Analysis
# =============================================================================
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers via SSH and collects detailed OSPF
#   neighbor information, flagging adjacencies stuck in non-Full states and
#   reporting DR/BDR election status, dead timers, and interface costs.
#   Complements ospf_neighbors.pl (basic state) with deep adjacency analysis.
#
# Usage:
#   Single device:  ./ospf_neighbor_detail.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./ospf_neighbor_detail.pl -f devices.txt -u admin -p secret
#   With logging:   ./ospf_neighbor_detail.pl -h 10.0.0.1 -u admin -p secret -l ospf_detail.log
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH key auth or password auth to target devices
#   Read-only access (show commands only)
#
# Device file format: one IP or hostname per line, # for comments
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file, $help);
my $timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$log_file,
    't|timeout=i'  => \$timeout,
    'help'         => \$help,
) or die "Error in arguments. Use --help for usage.\n";

if ($help || (!$host && !$device_file) || !$username || !$password) {
    print "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOGFILE] [-t TIMEOUT]\n";
    exit 1;
}

my @devices = $host ? ($host) : load_devices($device_file);
die "No devices to process.\n" unless @devices;

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log file $log_file: $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
log_output("=" x 70);
log_output("OSPF Neighbor Detail Report - $timestamp");
log_output("=" x 70);

for my $device (@devices) {
    process_device($device, $username, $password, $timeout);
}

close($log_fh) if $log_fh;

sub process_device {
    my ($device, $user, $pass, $to) = @_;

    log_output("\n--- Device: $device ---");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password     => $pass,
        raw_pty     => 1,
        timeout     => $to,
    );

    eval {
        my $login_output = $ssh->login();
        if ($login_output !~ /[>#]/) {
            die "Authentication failed or unexpected prompt on $device\n";
        }
    };
    if ($@) {
        log_output("ERROR: Cannot connect to $device - $@");
        return;
    }

    $ssh->exec("terminal length 0");

    my $output = $ssh->exec("show ip ospf neighbor detail");
    unless (defined $output) {
        log_output("ERROR: No response from $device (timeout after ${to}s)");
        $ssh->close();
        return;
    }

    parse_ospf_detail($device, $output);

    $ssh->exec("exit");
    $ssh->close();
}

sub parse_ospf_detail {
    my ($device, $output) = @_;

    if ($output =~ /OSPF not enabled|% OSPF: No such process|no neighbor/i) {
        log_output("  INFO: OSPF not configured or no neighbors on $device");
        return;
    }

    my @blocks = split(/(?=Neighbor \d+\.\d+\.\d+\.\d+,)/, $output);
    my $neighbor_count = 0;
    my @warnings;

    for my $block (@blocks) {
        next unless $block =~ /Neighbor (\d+\.\d+\.\d+\.\d+)/;
        my $neighbor_id = $1;
        $neighbor_count++;

        my $state       = $block =~ /State is (\S+)/          ? $1 : 'Unknown';
        my $interface   = $block =~ /interface address (\S+)/i ? $1 : 'Unknown';
        my $area        = $block =~ /in the area (\S+)/        ? $1 : 'Unknown';
        my $priority    = $block =~ /Neighbor priority is (\d+)/ ? $1 : '?';
        my $dr          = $block =~ /DR is (\S+)/              ? $1 : 'None';
        my $bdr         = $block =~ /BDR is (\S+)/             ? $1 : 'None';
        my $dead_timer  = $block =~ /Dead timer due in ([\d:]+)/ ? $1 : '?';
        my $hello_int   = $block =~ /Hello due in ([\d:]+)/    ? $1 : '?';
        my $uptime      = $block =~ /Neighbor is up for ([\dhms:]+)/ ? $1 : '?';

        my $status = ($state eq 'FULL') ? 'OK' : 'WARN';
        log_output(sprintf("  [%s] Neighbor: %-16s  State: %-14s  Area: %s", $status, $neighbor_id, $state, $area));
        log_output(sprintf("       Interface: %-16s  Priority: %-3s  Uptime: %s", $interface, $priority, $uptime));
        log_output(sprintf("       DR: %-18s  BDR: %-18s  Dead: %s", $dr, $bdr, $dead_timer));

        push @warnings, "Neighbor $neighbor_id on $device stuck in state: $state"
            if $state !~ /^(FULL|2WAY)$/i;

        if ($dead_timer =~ /^0:0:0(\d+)$/ && $1 < 10) {
            push @warnings, "Neighbor $neighbor_id dead timer critically low: ${dead_timer}s";
        }
    }

    if ($neighbor_count == 0) {
        log_output("  INFO: No OSPF neighbors found on $device");
    } else {
        log_output("  Total neighbors: $neighbor_count");
    }

    if (@warnings) {
        log_output("  WARNINGS:");
        log_output("    ! $_") for @warnings;
    }
}

sub load_devices {
    my ($file) = @_;
    open(my $fh, '<', $file) or die "Cannot open device file $file: $!\n";
    my @list = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close($fh);
    return @list;
}

sub log_output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}
```