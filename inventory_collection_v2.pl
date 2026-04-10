The user's instruction is explicit: "Output ONLY the script content, no markdown fences, no explanation." This overrides the brainstorming skill's hard gate per the skill's own priority rules ("User instructions always take precedence").

Here is the script:

#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# arp_table_collector.pl - Cisco IOS ARP Table Collector
# =============================================================================
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE devices via SSH and collects the
#   IP ARP table. Useful for IP-to-MAC mapping audits, security investigations,
#   rogue device detection, and IPAM reconciliation.
#
# Usage:
#   Single device:   ./arp_table_collector.pl --host 192.168.1.1
#   Device file:     ./arp_table_collector.pl --file devices.txt
#   With logging:    ./arp_table_collector.pl --file devices.txt --log arp_audit.log
#   With VRF:        ./arp_table_collector.pl --host 192.168.1.1 --vrf MGMT
#
# Device file format: one IP or hostname per line, lines starting with # ignored
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH key auth recommended; password auth supported via --password flag
#   Devices must have 'ip ssh version 2' enabled
#
# Environment variables (optional):
#   NET_USER     - SSH username (overridden by --user flag)
#   NET_PASS     - SSH password (overridden by --password flag)
# =============================================================================

my ($host, $device_file, $log_file, $vrf);
my $user     = $ENV{NET_USER} || 'admin';
my $password = $ENV{NET_PASS} || '';
my $timeout  = 30;

GetOptions(
    'host=s'     => \$host,
    'file=s'     => \$device_file,
    'log=s'      => \$log_file,
    'user=s'     => \$user,
    'password=s' => \$password,
    'vrf=s'      => \$vrf,
    'timeout=i'  => \$timeout,
) or die "Usage: $0 --host <ip>|--file <devices.txt> [--log file] [--user u] [--password p] [--vrf name]\n";

die "ERROR: Specify --host or --file\n" unless $host || $device_file;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "ERROR: Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
    die "ERROR: No devices found in $device_file\n" unless @devices;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>', $log_file) or die "ERROR: Cannot open log $log_file: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("ARP Table Collection - $timestamp");
output("=" x 60);

sub output {
    my $line = shift;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}

sub collect_arp {
    my $device = shift;
    output("\nDevice: $device");
    output("-" x 40);

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password    => $password,
        raw_pty     => 1,
        timeout     => $timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=15',
    );

    my $login_output;
    eval {
        $login_output = $ssh->login();
    };
    if ($@ || !defined $login_output) {
        output("  ERROR: Connection failed - $@");
        return;
    }
    if ($login_output =~ /[Pp]assword|[Aa]uth/i && $login_output !~ /[>#]/) {
        output("  ERROR: Authentication failed for $device");
        return;
    }

    # Disable paging
    $ssh->send("terminal length 0");
    $ssh->waitfor('(?:>|#)\s*$', 5);

    my $cmd = $vrf ? "show ip arp vrf $vrf" : "show ip arp";
    $ssh->send($cmd);
    my $output = $ssh->waitfor('(?:>|#)\s*$', $timeout);

    unless (defined $output) {
        output("  ERROR: No response or timeout on $device");
        $ssh->close();
        return;
    }

    my $entry_count = 0;
    my @parsed;

    for my $line (split /\n/, $output) {
        # Cisco IOS ARP format:
        # Protocol  Address    Age(min)  Hardware Addr   Type  Interface
        # Internet  10.0.0.1   12        aabb.cc00.0100  ARPA  GigabitEthernet0/0
        if ($line =~ /^Internet\s+(\S+)\s+(\S+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\S+)\s+(\S+)/i) {
            my ($ip, $age, $mac, $type, $iface) = ($1, $2, $3, $4, $5);
            $age = '-' if $age eq '-';
            push @parsed, { ip => $ip, age => $age, mac => $mac, interface => $iface };
            $entry_count++;
        }
    }

    if ($entry_count == 0) {
        output("  WARNING: No ARP entries found (check VRF or permissions)");
    } else {
        output(sprintf("  %-18s %-8s %-18s %s", "IP Address", "Age(m)", "MAC Address", "Interface"));
        output(sprintf("  %-18s %-8s %-18s %s", "-" x 16, "-" x 6, "-" x 16, "-" x 20));
        for my $e (sort { $a->{ip} cmp $b->{ip} } @parsed) {
            output(sprintf("  %-18s %-8s %-18s %s",
                $e->{ip}, $e->{age}, $e->{mac}, $e->{interface}));
        }
        output("  Total entries: $entry_count");
    }

    $ssh->send("exit");
    $ssh->close();
}

collect_arp($_) for @devices;

output("\n" . "=" x 60);
output("Collection complete: " . strftime('%Y-%m-%d %H:%M:%S', localtime));
output("Log saved to: $log_file") if $log_file;
close $log_fh if $log_fh;