```perl
#!/usr/bin/perl
# =============================================================================
# ospf_neighbor_health.pl - OSPF Neighbor State Health Monitor
#
# Purpose:
#   Connects to one or more IOS/IOS-XE routers and performs an OSPF neighbor
#   health check. Flags neighbors not in FULL/2WAY state, reports dead-timer
#   values, DR/BDR roles, and cross-references neighbor count per interface.
#   Useful for pre/post-change validation and NOC triage.
#
# Usage:
#   Single device:  ./ospf_neighbor_health.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./ospf_neighbor_health.pl -f devices.txt -u admin -p secret
#   With log file:  ./ospf_neighbor_health.pl -f devices.txt -u admin -p secret -l /var/log/ospf_health.log
#
# Prerequisites:
#   cpan install Net::SSH::Expect Getopt::Long
#
# Device file format (one IP or hostname per line, # for comments):
#   192.168.1.1
#   192.168.1.2  # core-rtr-01
#
# Exit codes: 0=all neighbors healthy, 1=degraded neighbors found, 2=error
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file, $timeout);
$timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$log_file,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l <logfile>] [-t <timeout>]\n";

die "ERROR: Must specify -h <host> or -f <file>\n" unless $host || $device_file;
die "ERROR: Must specify -u <username>\n" unless $username;
die "ERROR: Must specify -p <password>\n" unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "ERROR: Cannot open device file '$device_file': $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or warn "WARNING: Cannot open log file '$log_file': $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
my $global_exit = 0;

sub log_output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

log_output("=" x 72 . "\n");
log_output("OSPF Neighbor Health Check - $timestamp\n");
log_output("=" x 72 . "\n\n");

for my $device (@devices) {
    log_output("Device: $device\n");
    log_output("-" x 50 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $username,
        password     => $password,
        raw_pty     => 1,
        timeout     => $timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=15',
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        log_output("  ERROR: Connection failed - $@\n\n");
        $global_exit = 2;
        next;
    }
    if ($login_output =~ /[Pp]assword|[Aa]uth/i && $login_output !~ /[>#]/) {
        log_output("  ERROR: Authentication failed for $device\n\n");
        $global_exit = 2;
        next;
    }

    # Disable paging
    $ssh->send("terminal length 0");
    $ssh->waitfor('[>#]', 5);

    # Collect OSPF neighbor detail
    $ssh->send("show ip ospf neighbor detail");
    my $neighbor_output = $ssh->waitfor('[>#]', $timeout) // '';

    # Collect OSPF interface summary for neighbor counts
    $ssh->send("show ip ospf interface brief");
    my $intf_output = $ssh->waitfor('[>#]', $timeout) // '';

    $ssh->send("exit");
    $ssh->close();

    # Parse neighbor detail blocks
    my @neighbors;
    my @blocks = split(/(?=Neighbor\s+\d+\.\d+\.\d+\.\d+)/i, $neighbor_output);

    for my $block (@blocks) {
        next unless $block =~ /Neighbor\s+(\d+\.\d+\.\d+\.\d+)/i;
        my %n;
        $n{router_id} = $1;
        $n{state}     = $block =~ /State is (\S+)/i        ? $1 : 'UNKNOWN';
        $n{address}   = $block =~ /Neighbor address (\S+)/i ? $1 : 'N/A';
        $n{interface} = $block =~ /Interface address.*?(?:,\s*interface\s+)?(\S+)/i ? $1
                      : $block =~ /on interface (\S+)/i ? $1 : 'N/A';
        $n{dead_timer}= $block =~ /Dead timer due in\s+(\S+)/i ? $1 : 'N/A';
        $n{priority}  = $block =~ /Neighbor priority is (\d+)/i ? $1 : 'N/A';
        $n{dr_role}   = $block =~ /\bDR\b/i && $block =~ /This router is the/i ? 'DR'
                      : $block =~ /\bBDR\b/i && $block =~ /This router is the/i ? 'BDR' : 'DROTHER';
        push @neighbors, \%n;
    }

    if (!@neighbors) {
        log_output("  No OSPF neighbors found\n\n");
        next;
    }

    my $degraded = 0;
    log_output(sprintf("  %-18s %-16s %-12s %-12s %s\n",
        "Neighbor-ID", "Address", "State", "Dead-Timer", "Interface"));
    log_output("  " . "-" x 68 . "\n");

    for my $n (@neighbors) {
        my $healthy = ($n->{state} =~ /^FULL|2WAY/i);
        $degraded++ unless $healthy;
        my $flag = $healthy ? '  ' : '! ';
        log_output(sprintf("%s%-18s %-16s %-12s %-12s %s\n",
            $flag, $n->{router_id}, $n->{address},
            $n->{state}, $n->{dead_timer}, $n->{interface}));
    }

    log_output("\n  Total neighbors: " . scalar(@neighbors));
    if ($degraded) {
        log_output("  |  DEGRADED: $degraded (marked with !)\n");
        $global_exit = 1 unless $global_exit == 2;
    } else {
        log_output("  |  All neighbors healthy\n");
    }
    log_output("\n");
}

log_output("=" x 72 . "\n");
log_output("Check complete. Exit status: $global_exit\n");
log_output("  0=healthy  1=degraded neighbors  2=connection errors\n");
log_output("=" x 72 . "\n");

close $log_fh if $log_fh;
exit $global_exit;
```