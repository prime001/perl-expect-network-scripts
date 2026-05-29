The write was blocked by permissions. Here is the complete script content — you can save it as `cdp_lldp_topology.pl`:

```perl
#!/usr/bin/perl
#
# cdp_lldp_topology.pl - CDP/LLDP Neighbor Topology Mapper
#
# PURPOSE:
#   Connects to one or more Cisco (or compatible) network devices via SSH and
#   collects CDP or LLDP neighbor adjacency data to produce a structured
#   topology map. Useful for network documentation, change verification after
#   a cutover, and detecting unexpected or rogue adjacencies.
#
# USAGE:
#   Single device:  perl cdp_lldp_topology.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    perl cdp_lldp_topology.pl -f devices.txt -u admin -p secret
#   LLDP mode:      perl cdp_lldp_topology.pl -f devices.txt -u admin -p secret --lldp
#   With log:       perl cdp_lldp_topology.pl -f devices.txt -u admin -p secret -l topo.log
#
# PREREQUISITES:
#   cpanm Net::SSH::Expect Getopt::Long
#   CDP or LLDP must be enabled on target devices.
#   SSH access with credentials that have at least read-only privilege.
#
# DEVICE FILE FORMAT:
#   One IP or hostname per line; lines beginning with # are ignored.
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file, $use_lldp);
my $timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$device_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'l|log=s'     => \$log_file,
    't|timeout=i' => \$timeout,
    'lldp'        => \$use_lldp,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOG] [--lldp]\n";

die "Provide -h HOST or -f FILE\n"    unless $host || $device_file;
die "Username required: -u USER\n"   unless $username;
die "Password required: -p PASS\n"   unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if $_ }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub out {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}

sub query_device {
    my ($device) = @_;
    out("\n--- $device ---");

    my $ssh = eval {
        my $s = Net::SSH::Expect->new(
            host     => $device,
            user     => $username,
            password => $password,
            raw_pty  => 1,
            timeout  => $timeout,
        );
        $s->run_ssh() or die "SSH handshake failed\n";
        $s->read_all(2);
        $s;
    };
    if ($@) {
        out("  ERROR: $@");
        return;
    }

    $ssh->send("terminal length 0\n"); $ssh->read_all(2);

    my $cmd = $use_lldp ? 'show lldp neighbors detail' : 'show cdp neighbors detail';
    $ssh->send("$cmd\n");
    my $raw = $ssh->read_all(4);

    $ssh->send("exit\n");
    eval { $ssh->close() };

    parse_neighbors($device, $raw);
}

sub parse_neighbors {
    my ($device, $raw) = @_;
    my @neighbors;

    if (!$use_lldp) {
        for my $block (split /(?=Device ID:)/, $raw) {
            my %n;
            ($n{id})      = $block =~ /Device ID:\s*(\S+)/;
            ($n{ip})      = $block =~ /IP(?:v4)? address:\s*(\d[\d.]+)/i;
            ($n{platform})= $block =~ /Platform:\s*([^,\n]+)/;
            ($n{local})   = $block =~ /Interface:\s*(\S+)/;
            ($n{remote})  = $block =~ /Port ID[^:]*:\s*(\S+)/;
            push @neighbors, \%n if $n{id};
        }
    } else {
        for my $block (split /(?=Local Intf:)/, $raw) {
            my %n;
            ($n{id})      = $block =~ /System Name:\s*(\S+)/;
            ($n{ip})      = $block =~ /(?:Management Addresses?|IP(?:v4)?)[^\d]*(\d[\d.]+)/i;
            ($n{platform})= $block =~ /System Description:\s*([^\n]+)/;
            ($n{local})   = $block =~ /Local Intf:\s*(\S+)/;
            ($n{remote})  = $block =~ /Port id:\s*(\S+)/i;
            push @neighbors, \%n if $n{id};
        }
    }

    unless (@neighbors) {
        out("  No " . ($use_lldp ? "LLDP" : "CDP") . " neighbors found");
        return;
    }

    out(sprintf("  %-24s %-16s %-22s %-22s", "Neighbor", "IP", "Local Intf", "Remote Intf"));
    out("  " . "-" x 84);
    for my $n (@neighbors) {
        out(sprintf("  %-24s %-16s %-22s %-22s",
            substr($n{id}     // '?',   0, 24),
            substr($n{ip}     // 'N/A', 0, 16),
            substr($n{local}  // '?',   0, 22),
            substr($n{remote} // '?',   0, 22),
        ));
    }
    out("  Neighbors: " . scalar(@neighbors));
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
out("CDP/LLDP Topology Map  [" . ($use_lldp ? "LLDP" : "CDP") . "]  $ts");
out("=" x 60);

query_device($_) for @devices;

out("\n" . "=" x 60);
out("Done. Devices queried: " . scalar(@devices));
out("Log: $log_file") if $log_file;

close $log_fh if $log_fh;
```

**What it does:** SSHes to each device, disables paging, runs `show cdp neighbors detail` (or `show lldp neighbors detail` with `--lldp`), parses neighbor blocks using targeted regexes, and prints a columnar table — Neighbor / IP / Local Intf / Remote Intf — per device. Error handling covers connection failures, SSH handshake errors, and unreachable hosts without killing the entire run. Output goes to STDOUT and optionally a timestamped log file.