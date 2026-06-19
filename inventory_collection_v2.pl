The user wants the script content as output only. Here it is:

#!/usr/bin/perl
#
# cdp_lldp_neighbors.pl — CDP/LLDP Neighbor Discovery
#
# Purpose:
#   Collects CDP and LLDP neighbor information from Cisco IOS/IOS-XE devices
#   to map physical topology, verify cabling, and audit adjacency relationships.
#   Useful for validating network diagrams or discovering unknown attachments
#   before/after a change window.
#
# Usage:
#   perl cdp_lldp_neighbors.pl -h <host> [-u <user>] [-p <pass>] [-o <file>] [-t <sec>]
#   perl cdp_lldp_neighbors.pl -f <device_list> [-u <user>] [-p <pass>] [-o <file>]
#
#   -h  Single device IP or hostname
#   -f  File containing one device per line (blank lines and # comments ignored)
#   -u  SSH username  (default: $NET_USER env var)
#   -p  SSH password  (default: $NET_PASS env var)
#   -o  Optional output log file (appends run timestamp header)
#   -t  SSH/expect timeout in seconds (default: 30)
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Std
#   SSH key-based auth or password via env vars NET_USER / NET_PASS
#
# Notes:
#   Requires IOS "terminal length 0" to disable paging.
#   LLDP section is skipped silently if LLDP is not enabled on the device.
#   StrictHostKeyChecking is disabled — suitable for lab/private networks only.

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);

$Getopt::Std::STANDARD_HELP_VERSION = 1;

my %opts;
getopts('h:f:u:p:o:t:', \%opts) or die usage();

my $username = $opts{u} // $ENV{NET_USER} // die "No username: supply -u or set NET_USER\n";
my $password = $opts{p} // $ENV{NET_PASS} // die "No password: supply -p or set NET_PASS\n";
my $timeout  = $opts{t} // 30;

die usage() unless $opts{h} || $opts{f};

my @devices;
push @devices, $opts{h} if $opts{h};
if ($opts{f}) {
    open my $fh, '<', $opts{f} or die "Cannot open device file '$opts{f}': $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if $_; }
    close $fh;
}
die "No devices found to poll.\n" unless @devices;

my $log_fh;
if ($opts{o}) {
    open $log_fh, '>', $opts{o} or die "Cannot open log file '$opts{o}': $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub usage { "Usage: $0 -h <host>|-f <file> [-u user] [-p pass] [-o logfile] [-t secs]\n" }

sub poll_device {
    my ($host) = @_;

    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        user       => $username,
        password   => $password,
        timeout    => $timeout,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=15 -o BatchMode=no',
    );

    eval { $ssh->login() };
    if ($@) {
        out("ERROR [$host]: login failed — $@\n");
        return;
    }

    $ssh->exec("terminal length 0");

    out("\n" . "=" x 72 . "\n");
    out(sprintf("Host: %-40s  Polled: %s\n", $host, strftime("%Y-%m-%d %H:%M:%S", localtime)));
    out("=" x 72 . "\n");

    my $cdp  = $ssh->exec("show cdp neighbors detail");
    parse_cdp($cdp)   if $cdp  && $cdp  !~ /not enabled|CDP is not/i;

    my $lldp = $ssh->exec("show lldp neighbors detail");
    parse_lldp($lldp) if $lldp && $lldp !~ /not enabled|LLDP is not/i;

    $ssh->close();
}

sub parse_cdp {
    my ($raw) = @_;
    out("\n  -- CDP Neighbors --\n");
    out(sprintf("  %-28s %-18s %-18s %-22s %-15s\n",
        "Neighbor", "Local Intf", "Remote Intf", "Platform", "Mgmt IP"));
    out("  " . "-" x 103 . "\n");

    my $count = 0;
    for my $block (split /---+/, $raw) {
        next unless $block =~ /Device ID/i;
        my ($nbr)      = $block =~ /Device ID:\s*(\S+)/i;
        my ($local_if) = $block =~ /Interface:\s*(\S+)/i;
        my ($rem_if)   = $block =~ /Port ID[^:]*:\s*(\S+)/i;
        my ($platform) = $block =~ /Platform:\s*([^,\n]+)/i;
        my ($mgmt_ip)  = $block =~ /IP(?:v4)? [Aa]ddress:\s*([\d.]+)/;

        $platform = substr($platform // 'unknown', 0, 20);
        $platform =~ s/\s+$//;
        out(sprintf("  %-28s %-18s %-18s %-22s %-15s\n",
            substr($nbr // 'unknown', 0, 27),
            $local_if // 'unknown',
            $rem_if   // 'unknown',
            $platform,
            $mgmt_ip  // 'N/A'));
        $count++;
    }
    out("  (no CDP neighbors)\n") unless $count;
}

sub parse_lldp {
    my ($raw) = @_;
    return unless $raw =~ /System Name|Chassis id|Port Description/i;

    out("\n  -- LLDP Neighbors --\n");
    out(sprintf("  %-28s %-18s %-22s %-15s\n",
        "System Name", "Local Intf", "Remote Port", "Mgmt IP"));
    out("  " . "-" x 85 . "\n");

    my $count = 0;
    for my $block (split /Local Intf:/i, $raw) {
        next unless $block =~ /System Name/i;
        my ($local_if) = $block =~ /^\s*(\S+)/;
        my ($sys_name) = $block =~ /System Name:\s*(\S+)/i;
        my ($port_id)  = $block =~ /Port id:\s*(\S+)/i;
        my ($mgmt_ip)  = $block =~ /(?:IP|IPv4):\s*([\d.]+)/i;

        out(sprintf("  %-28s %-18s %-22s %-15s\n",
            substr($sys_name // 'unknown', 0, 27),
            $local_if // 'unknown',
            $port_id  // 'unknown',
            $mgmt_ip  // 'N/A'));
        $count++;
    }
    out("  (no LLDP neighbors)\n") unless $count;
}

my $started = time();
out("CDP/LLDP Neighbor Discovery — " . strftime("%Y-%m-%d %H:%M:%S", localtime) . "\n");
out("Devices: " . scalar(@devices) . ($opts{o} ? "  |  Log: $opts{o}" : "") . "\n");

poll_device($_) for @devices;

out("\n" . "=" x 72 . "\n");
out(sprintf("Done. %d device(s) polled in %ds.\n", scalar(@devices), time() - $started));
out("Results written to: $opts{o}\n") if $opts{o};

close $log_fh if $log_fh;