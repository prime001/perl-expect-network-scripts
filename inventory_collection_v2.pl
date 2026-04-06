#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# cdp_lldp_topology.pl - CDP/LLDP Neighbor Discovery and Topology Mapper
#
# PURPOSE:
#   Connects to one or more Cisco IOS/NX-OS devices via SSH and collects
#   CDP and LLDP neighbor detail, producing a structured topology snapshot
#   useful for network documentation and change management audits.
#
# USAGE:
#   Single device:  ./cdp_lldp_topology.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./cdp_lldp_topology.pl -f devices.txt -u admin -p secret
#   With log file:  ./cdp_lldp_topology.pl -f devices.txt -u admin -p secret -l topology.log
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   SSH access to target devices (privilege level 1 sufficient)
#   CDP and/or LLDP enabled on target devices
#
# OUTPUT FORMAT:
#   LOCAL_DEVICE | LOCAL_PORT | NEIGHBOR | NEIGHBOR_IP | NEIGHBOR_PORT | PLATFORM | PROTOCOL
# =============================================================================

my ($host, $device_file, $username, $password, $log_file, $timeout);
$timeout = 15;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$log_file,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h <host>|-f <file> -u <user> -p <pass> [-l <logfile>] [-t <timeout>]\n";

die "Provide -h <host> or -f <file>\n" unless $host || $device_file;
die "Username (-u) required\n" unless $username;
die "Password (-p) required\n" unless $password;

my @devices = $host ? ($host) : ();
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if $_; }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    print $log_fh "\n# CDP/LLDP Topology Run: $ts\n";
}

sub output {
    my $line = shift;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}

sub collect_neighbors {
    my ($device) = @_;
    output("# === $device ===");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $username,
        password    => $password,
        timeout     => $timeout,
        raw_pty     => 1,
    );

    eval { $ssh->login() };
    if ($@) {
        output("# ERROR [$device]: Connection/auth failed - $@");
        return;
    }

    $ssh->exec("terminal length 0");

    for my $proto ('cdp', 'lldp') {
        my $cmd = "show ${proto} neighbors detail";
        my $out = $ssh->exec($cmd);

        unless (defined $out && length $out > 10) {
            output("# INFO [$device]: No ${proto} output (disabled or unsupported)");
            next;
        }

        my ($local_port, $neighbor, $neighbor_ip, $neighbor_port, $platform);

        for my $line (split /\n/, $out) {
            $line =~ s/\r//g;

            if ($line =~ /^Device ID:\s*(.+)$/i)                          { $neighbor      = $1; $neighbor =~ s/\s+$//; }
            if ($line =~ /IP(?:v4)?\s+[Aa]ddress:\s*([\d.]+)/)            { $neighbor_ip   = $1; }
            if ($line =~ /Platform:\s*([^,]+)/i)                           { ($platform = $1) =~ s/\s+$//; }
            if ($line =~ /Interface:\s*([\w\/\.]+),.*Port ID.*:\s*(.+)$/i) { $local_port = $1; $neighbor_port = $2; $neighbor_port =~ s/\s+$//; }

            if ($neighbor && $local_port && $neighbor_port) {
                $neighbor_ip //= 'N/A';
                $platform    //= 'Unknown';
                output(sprintf("%-20s | %-20s | %-30s | %-16s | %-20s | %-20s | %s",
                    $device, $local_port, $neighbor, $neighbor_ip, $neighbor_port, $platform, uc($proto)));
                ($local_port, $neighbor, $neighbor_ip, $neighbor_port, $platform) = (undef) x 5;
            }
        }
    }

    $ssh->close();
}

output(sprintf("%-20s | %-20s | %-30s | %-16s | %-20s | %-20s | %s",
    'LOCAL_DEVICE', 'LOCAL_PORT', 'NEIGHBOR', 'NEIGHBOR_IP', 'NEIGHBOR_PORT', 'PLATFORM', 'PROTOCOL'));
output('-' x 140);

collect_neighbors($_) for @devices;

close $log_fh if $log_fh;