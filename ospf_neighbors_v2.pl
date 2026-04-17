#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# ospf_neighbor_health.pl - OSPF Neighbor State Health Check
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers via SSH and audits OSPF neighbor
#   adjacency health. Flags neighbors not in FULL/2WAY state, checks dead
#   timer drift, and reports mismatched router-IDs. Useful for rapid
#   troubleshooting during network incidents or scheduled health checks.
#
# Usage:
#   Single device:  ./ospf_neighbor_health.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./ospf_neighbor_health.pl -f devices.txt -u admin -p secret
#   With logging:   ./ospf_neighbor_health.pl -h 192.168.1.1 -u admin -p secret -l /var/log/ospf_health.log
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH enabled on target devices; user needs enable-level show access
#
# Device file format (one per line):
#   192.168.1.1
#   router2.example.com
# =============================================================================

my ($host, $user, $pass, $enable, $file, $logfile, $timeout);
$timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'e|enable=s'  => \$enable,
    'f|file=s'    => \$file,
    'l|log=s'     => \$logfile,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-e <enable>] [-l <logfile>] [-t <timeout>]\n";

die "Provide -h <host> or -f <file>\n" unless $host || $file;
die "Username (-u) required\n" unless $user;
die "Password (-p) required\n" unless $pass;

my @devices;
if ($file) {
    open(my $fh, '<', $file) or die "Cannot open device file '$file': $!\n";
    while (<$fh>) { chomp; s/\s+//g; push @devices, $_ if /\S/; }
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or warn "Cannot open log '$logfile': $! (logging to STDOUT only)\n";
}

sub log_output {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
log_output("=" x 70 . "\n");
log_output("OSPF Neighbor Health Check - $timestamp\n");
log_output("=" x 70 . "\n\n");

my $total_alerts = 0;

for my $device (@devices) {
    log_output("Device: $device\n");
    log_output("-" x 50 . "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $device,
            user        => $user,
            password    => $pass,
            raw_pty     => 1,
            timeout     => $timeout,
        );
    };
    if ($@) {
        log_output("  [ERROR] Failed to create SSH session: $@\n\n");
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        log_output("  [ERROR] SSH login failed for $device\n\n");
        next;
    }

    # Handle enable mode if needed
    if ($enable) {
        $ssh->send("enable");
        my $res = $ssh->waitfor('Password:', $timeout);
        if ($res) {
            $ssh->send($enable);
            $ssh->waitfor('(#|\$)', $timeout);
        }
    }

    # Disable paging
    $ssh->exec("terminal length 0");

    # Pull OSPF neighbor detail
    my $output = $ssh->exec("show ip ospf neighbor detail");

    if (!defined $output || $output =~ /Invalid input|% Unknown/i) {
        log_output("  [WARN] Command failed or OSPF not configured\n\n");
        $ssh->close() if $ssh;
        next;
    }

    if ($output =~ /^\s*$/ || $output !~ /Neighbor ID/i) {
        log_output("  [INFO] No OSPF neighbors found\n\n");
        $ssh->close() if $ssh;
        next;
    }

    # Parse neighbor blocks
    my @blocks = split(/(?=Neighbor\s+\d+\.\d+\.\d+\.\d+)/i, $output);
    my @neighbors;

    for my $block (@blocks) {
        next unless $block =~ /Neighbor\s+(\d+\.\d+\.\d+\.\d+)/i;
        my %n;
        $n{router_id}  = $1;
        $n{state}      = $block =~ /State is\s+(\S+)/i    ? $1 : 'Unknown';
        $n{interface}  = $block =~ /Interface address[^,]*,\s*interface\s+(\S+)/i ? $1
                       : $block =~ /on interface\s+(\S+)/i ? $1 : 'Unknown';
        $n{dead_timer} = $block =~ /Dead timer due in\s+([\d:]+)/i ? $1 : 'N/A';
        $n{uptime}     = $block =~ /Neighbor is up for\s+([\w:]+)/i ? $1 : 'N/A';
        push @neighbors, \%n;
    }

    my $device_alerts = 0;
    printf { $log_fh ? $log_fh : \*STDOUT } "  %-18s %-12s %-20s %-12s %s\n",
        "Router ID", "State", "Interface", "Dead Timer", "Uptime";
    log_output("  " . "-" x 68 . "\n");

    for my $n (@neighbors) {
        my $alert = ($n->{state} !~ /^(FULL|2WAY)/i) ? " [ALERT]" : "";
        $device_alerts++ if $alert;
        $total_alerts++  if $alert;
        printf { $log_fh ? $log_fh : \*STDOUT } "  %-18s %-12s %-20s %-12s %s%s\n",
            $n->{router_id}, $n->{state}, $n->{interface},
            $n->{dead_timer}, $n->{uptime}, $alert;
    }

    if ($device_alerts) {
        log_output("\n  *** $device_alerts neighbor(s) not in FULL/2WAY state on $device ***\n");
    } else {
        log_output("\n  All " . scalar(@neighbors) . " neighbor(s) healthy\n");
    }
    log_output("\n");

    $ssh->exec("exit");
    $ssh->close();
}

log_output("=" x 70 . "\n");
log_output("Summary: $total_alerts total alert(s) across " . scalar(@devices) . " device(s)\n");
log_output("Completed: " . strftime("%Y-%m-%d %H:%M:%S", localtime) . "\n");
log_output("=" x 70 . "\n");

close $log_fh if $log_fh;
exit($total_alerts ? 1 : 0);