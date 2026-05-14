Since I can't write to that path, here is the script content as requested:

#!/usr/bin/perl
# cdp_neighbors.pl - CDP/LLDP Neighbor Discovery and Topology Mapper
#
# PURPOSE:
#   Collects CDP and LLDP neighbor information from Cisco IOS/NX-OS devices
#   to build a layer-2 adjacency map. Useful for topology validation,
#   change-impact analysis, and discovering undocumented links.
#
# USAGE:
#   Single device:   ./cdp_neighbors.pl -h 192.168.1.1 -u admin -p secret
#   Device list:     ./cdp_neighbors.pl -f devices.txt -u admin -p secret
#   With log file:   ./cdp_neighbors.pl -h 10.0.0.1 -u admin -p secret -l neighbors.log
#   LLDP mode:       ./cdp_neighbors.pl -h 10.0.0.1 -u admin -p secret --lldp
#
# PREREQUISITES:
#   cpanm Net::SSH::Expect
#   SSH access to target devices (port 22)
#   Account with at minimum 'show' privilege level
#
# OUTPUT:
#   Tabular neighbor summary with local port, remote device, remote port,
#   platform, and management IP.

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $pass, $device_file, $log_file, $use_lldp, $timeout);
$timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'f|file=s'     => \$device_file,
    'l|log=s'      => \$log_file,
    'lldp'         => \$use_lldp,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h HOST -u USER -p PASS [-f FILE] [-l LOGFILE] [--lldp]\n";

die "Provide -h HOST or -f FILE\n" unless $host || $device_file;
die "Username required (-u)\n"     unless $user;
die "Password required (-p)\n"     unless $pass;

my @devices = $host ? ($host) : do {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
};

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub output {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub collect_neighbors {
    my ($device) = @_;
    my $cmd      = $use_lldp ? 'show lldp neighbors detail' : 'show cdp neighbors detail';
    my $protocol = $use_lldp ? 'LLDP' : 'CDP';

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    eval {
        my $login = $ssh->login();
        die "Auth failed" unless $login =~ /[>#]/;
    };
    if ($@) {
        output(sprintf "[%-20s] ERROR: Cannot connect - %s\n", $device, $@);
        return;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('\s*[>#]', 5);
    $ssh->send($cmd);
    my $output = $ssh->waitfor('\s*[>#]', $timeout);
    $ssh->send('exit');
    $ssh->close();

    return parse_neighbors($device, $output, $protocol);
}

sub parse_neighbors {
    my ($device, $raw, $protocol) = @_;
    my @neighbors;
    my %current;

    for my $line (split /\n/, $raw) {
        $line =~ s/\r//g;

        if ($protocol eq 'CDP') {
            $current{device_id} = $1 if $line =~ /^Device ID:\s*(\S+)/;
            $current{mgmt_ip}   = $1 if $line =~ /IP(?:v4)? [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)/;
            $current{platform}  = $1 if $line =~ /Platform:\s*([^,]+)/;
            $current{local_if}  = $1 if $line =~ /Interface:\s*(\S+),/;
            $current{remote_if} = $1 if $line =~ /Port ID \(outgoing port\):\s*(\S+)/;
        } else {
            $current{device_id} = $1 if $line =~ /System Name:\s*(\S+)/;
            $current{mgmt_ip}   = $1 if $line =~ /Management Addresses.*?(\d+\.\d+\.\d+\.\d+)/s;
            $current{platform}  = $1 if $line =~ /System Description:\s*(.+)/;
            $current{local_if}  = $1 if $line =~ /Local Intf:\s*(\S+)/;
            $current{remote_if} = $1 if $line =~ /Port id:\s*(\S+)/;
        }

        if ($line =~ /^-{3,}/ && %current && $current{device_id}) {
            push @neighbors, {%current};
            %current = ();
        }
    }
    push @neighbors, {%current} if %current && $current{device_id};

    return ($device, \@neighbors);
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("\n=== CDP/LLDP Neighbor Discovery  [$ts] ===\n");
output(sprintf "%-20s %-22s %-20s %-22s %-16s\n",
    'Source Device', 'Local Interface', 'Neighbor', 'Remote Interface', 'Mgmt IP');
output('-' x 102 . "\n");

my $total_neighbors = 0;
for my $device (@devices) {
    my ($src, $neighbors) = collect_neighbors($device);
    next unless defined $neighbors;

    if (!@$neighbors) {
        output(sprintf "%-20s  No %s neighbors found\n", $device, $use_lldp ? 'LLDP' : 'CDP');
        next;
    }

    for my $n (@$neighbors) {
        output(sprintf "%-20s %-22s %-20s %-22s %-16s\n",
            $device,
            $n->{local_if}  // 'unknown',
            $n->{device_id} // 'unknown',
            $n->{remote_if} // 'unknown',
            $n->{mgmt_ip}   // 'N/A',
        );
        $total_neighbors++;
    }
}

output('-' x 102 . "\n");
output(sprintf "Total neighbors discovered: %d across %d device(s)\n", $total_neighbors, scalar @devices);
output("Log written to: $log_file\n") if $log_file;
close $log_fh if $log_fh;