```perl
#!/usr/bin/perl
#
# cdp_lldp_neighbors.pl - CDP/LLDP Neighbor Discovery and Topology Mapper
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE/NX-OS devices via SSH and collects CDP and
#   LLDP neighbor information to map adjacent devices. Useful for topology
#   documentation, change validation, and troubleshooting unknown adjacencies.
#
# Usage:
#   Single device:   ./cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin -p secret
#   Device list:     ./cdp_lldp_neighbors.pl -f devices.txt -u admin -p secret
#   With log file:   ./cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin -p secret -l neighbors.log
#   LLDP only:       ./cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin -p secret --lldp
#
# Prerequisites:
#   - Perl modules: Net::SSH::Expect, Getopt::Long
#   - SSH access to target devices
#   - CDP or LLDP enabled on target devices
#   - Install: cpan Net::SSH::Expect
#
# Output:
#   Formatted neighbor table with local port, remote device, remote port,
#   platform, and management IP per neighbor entry.
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $device_file, $username, $password, $log_file, $use_lldp, $timeout);
$timeout = 30;

GetOptions(
    'h|host=s'     => \$host_arg,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$log_file,
    'lldp'         => \$use_lldp,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h <host>|-f <file> -u <user> -p <pass> [-l logfile] [--lldp]\n";

die "Provide -h <host> or -f <file>\n" unless $host_arg || $device_file;
die "Username required (-u)\n" unless $username;
die "Password required (-p)\n" unless $password;

my @hosts = $host_arg ? ($host_arg) : ();
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; push @hosts, $_ if /\S/ && !/^#/; }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

sub log_output {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub parse_cdp_neighbors {
    my $output = shift;
    my @neighbors;
    my %entry;

    for my $line (split /\n/, $output) {
        if ($line =~ /^Device ID:\s*(.+)/)        { %entry = (device => $1) }
        elsif ($line =~ /IP address:\s*(\S+)/)     { $entry{mgmt_ip} //= $1 }
        elsif ($line =~ /Platform:\s*([^,]+)/)     { $entry{platform} = $1 }
        elsif ($line =~ /Interface:\s*(\S+),\s*Port ID.*?:\s*(\S+)/) {
            $entry{local_port}  = $1;
            $entry{remote_port} = $2;
        }
        elsif ($line =~ /^-{3,}/ && $entry{device}) {
            push @neighbors, {%entry};
            %entry = ();
        }
    }
    push @neighbors, {%entry} if $entry{device};
    return @neighbors;
}

sub parse_lldp_neighbors {
    my $output = shift;
    my @neighbors;
    my %entry;

    for my $line (split /\n/, $output) {
        if ($line =~ /^Local Intf:\s*(\S+)/)           { %entry = (local_port => $1) }
        elsif ($line =~ /System Name:\s*(.+)/)          { $entry{device} = $1 }
        elsif ($line =~ /Port id:\s*(\S+)/)             { $entry{remote_port} = $1 }
        elsif ($line =~ /System Description:\s*(.+)/)   { $entry{platform} = substr($1, 0, 40) }
        elsif ($line =~ /Management Address:\s*(\S+)/)  { $entry{mgmt_ip} //= $1 }
        elsif ($line =~ /^-{3,}/ && $entry{device}) {
            push @neighbors, {%entry};
            %entry = ();
        }
    }
    push @neighbors, {%entry} if $entry{device};
    return @neighbors;
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
log_output("=" x 70 . "\n");
log_output("CDP/LLDP Neighbor Discovery  |  $timestamp\n");
log_output("Protocol: " . ($use_lldp ? "LLDP" : "CDP") . "\n");
log_output("=" x 70 . "\n\n");

for my $host (@hosts) {
    log_output("Device: $host\n");
    log_output("-" x 70 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $username,
        password    => $password,
        timeout     => $timeout,
        raw_pty     => 1,
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        log_output("  ERROR: SSH connection failed to $host: $@\n\n");
        next;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\S+[>#]', 5);

    my $cmd = $use_lldp ? "show lldp neighbors detail" : "show cdp neighbors detail";
    $ssh->send("$cmd\n");
    my $output = $ssh->waitfor('\S+[>#]', $timeout);

    if (!defined $output || $output =~ /Invalid|Error|not enabled/i) {
        log_output("  WARNING: Command failed or protocol not enabled on $host\n");
        log_output("  Output: " . ($output // 'none') . "\n\n");
        $ssh->close();
        next;
    }

    my @neighbors = $use_lldp ? parse_lldp_neighbors($output) : parse_cdp_neighbors($output);

    if (!@neighbors) {
        log_output("  No neighbors found.\n\n");
    } else {
        log_output(sprintf("  %-22s %-30s %-22s %-16s\n",
            "LOCAL PORT", "NEIGHBOR DEVICE", "REMOTE PORT", "MGMT IP"));
        log_output("  " . "-" x 92 . "\n");
        for my $n (@neighbors) {
            log_output(sprintf("  %-22s %-30s %-22s %-16s\n",
                $n->{local_port}  // 'unknown',
                $n->{device}      // 'unknown',
                $n->{remote_port} // 'unknown',
                $n->{mgmt_ip}     // 'n/a'));
            log_output(sprintf("  %54s Platform: %s\n", '', $n->{platform} // 'unknown'))
                if $n->{platform};
        }
        log_output("\n  Total neighbors: " . scalar(@neighbors) . "\n");
    }

    $ssh->send("exit\n");
    $ssh->close();
    log_output("\n");
}

log_output("Run complete.\n");
close $log_fh if $log_fh;
```