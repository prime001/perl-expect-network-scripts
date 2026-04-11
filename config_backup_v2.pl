```perl
#!/usr/bin/perl
# =============================================================================
# cdp_lldp_neighbors.pl - CDP/LLDP Neighbor Discovery and Topology Mapper
# =============================================================================
# Purpose:
#   Connects to one or more network devices via SSH and collects CDP and LLDP
#   neighbor information. Useful for topology discovery, documentation, and
#   verifying adjacencies after network changes.
#
# Usage:
#   Single device:  ./cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin -p secret
#   Device list:    ./cdp_lldp_neighbors.pl -f devices.txt -u admin -p secret
#   With log file:  ./cdp_lldp_neighbors.pl -h 10.0.0.1 -u admin -p secret -l neighbors.log
#   Enable mode:    ./cdp_lldp_neighbors.pl -h 10.0.0.1 -u admin -p cisco -e enablepass
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH access to target devices (Cisco IOS/IOS-XE/NX-OS)
#   CDP and/or LLDP enabled on target devices
#
# Device file format (one per line, lines starting with # ignored):
#   192.168.1.1
#   router-core-01.example.com
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $username, $password, $enable_pass, $logfile, $help);
my $timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'e|enable=s'   => \$enable_pass,
    'l|log=s'      => \$logfile,
    't|timeout=i'  => \$timeout,
    'help'         => \$help,
) or die "Error parsing options. Use --help for usage.\n";

if ($help || (!$host && !$file) || !$username || !$password) {
    print "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-e <enable>] [-l <logfile>] [-t <timeout>]\n";
    exit 1;
}

my @devices;
if ($host) {
    push @devices, $host;
} elsif ($file) {
    open(my $fh, '<', $file) or die "Cannot open device file '$file': $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^\s*#/;
        push @devices, $_;
    }
    close $fh;
}

die "No devices to process.\n" unless @devices;

my $log_fh;
if ($logfile) {
    open($log_fh, '>', $logfile) or die "Cannot open log file '$logfile': $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
output("=" x 70);
output("CDP/LLDP Neighbor Discovery Report");
output("Generated: $timestamp");
output("=" x 70);

for my $device (@devices) {
    output("\n[*] Connecting to $device...");
    eval { process_device($device) };
    if ($@) {
        output("[!] ERROR on $device: $@");
    }
}

output("\n" . "=" x 70);
output("Scan complete.");
close $log_fh if $log_fh;

sub process_device {
    my ($dev) = @_;

    my $ssh = Net::SSH::Expect->new(
        host        => $dev,
        user        => $username,
        password    => $password,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        die "SSH login failed (check credentials or reachability)\n";
    }

    if ($login =~ /Password:\s*$/i || $login =~ /authentication failed/i) {
        die "Authentication failed\n";
    }

    # Disable pagination
    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$\s*$|#\s*$|>\s*$', $timeout);

    # Enter enable mode if password provided
    if ($enable_pass && $login =~ />\s*$/) {
        $ssh->send("enable\n");
        $ssh->waitfor('Password:', 5);
        $ssh->send("$enable_pass\n");
        my $resp = $ssh->waitfor('#\s*$', 5);
        die "Enable authentication failed\n" unless defined $resp;
    }

    output("\n--- Device: $dev ---");

    # Collect CDP neighbors
    $ssh->send("show cdp neighbors detail\n");
    my $cdp_output = $ssh->waitfor('#\s*$|>\s*$', $timeout);
    parse_cdp($cdp_output) if defined $cdp_output;

    # Collect LLDP neighbors
    $ssh->send("show lldp neighbors detail\n");
    my $lldp_output = $ssh->waitfor('#\s*$|>\s*$', $timeout);
    parse_lldp($lldp_output) if defined $lldp_output;

    $ssh->send("exit\n");
    $ssh->close();
}

sub parse_cdp {
    my ($raw) = @_;
    my @entries = split(/[-]{5,}/, $raw);
    my $count = 0;

    for my $entry (@entries) {
        next unless $entry =~ /Device ID/i;
        my %nbr;
        ($nbr{device_id})   = $entry =~ /Device ID:\s*(\S+)/i;
        ($nbr{platform})    = $entry =~ /Platform:\s*([^,]+)/i;
        ($nbr{local_intf})  = $entry =~ /Interface:\s*(\S+)/i;
        ($nbr{remote_intf}) = $entry =~ /Port ID \(outgoing port\):\s*(\S+)/i;
        ($nbr{ip_addr})     = $entry =~ /IP(?:v4)? address:\s*(\S+)/i;
        ($nbr{version})     = $entry =~ /Version\s*:\s*\n\s*(.+)/i;

        next unless $nbr{device_id};
        $count++;
        output(sprintf("  [CDP] %-30s  local:%-20s remote:%-20s ip:%s",
            $nbr{device_id} // 'unknown',
            $nbr{local_intf} // '?',
            $nbr{remote_intf} // '?',
            $nbr{ip_addr} // 'n/a'));
        output(sprintf("        Platform: %s", $nbr{platform} // 'unknown')) if $nbr{platform};
    }
    output("  [CDP] No neighbors found.") if $count == 0 && $raw !~ /Total cdp entries/i;
    output("  [CDP] CDP not enabled or no neighbors.") if $raw =~ /not enabled|CDP is not|% Invalid/i;
}

sub parse_lldp {
    my ($raw) = @_;
    return if $raw =~ /not enabled|LLDP is not|% Invalid|% LLDP/i;

    my @entries = split(/[-]{5,}/, $raw);
    my $count = 0;

    for my $entry (@entries) {
        next unless $entry =~ /System Name|Chassis id|Port Description/i;
        my %nbr;
        ($nbr{system_name}) = $entry =~ /System Name:\s*(\S+)/i;
        ($nbr{chassis_id})  = $entry =~ /Chassis id:\s*(\S+)/i;
        ($nbr{local_intf})  = $entry =~ /Local Intf:\s*(\S+)/i;
        ($nbr{port_id})     = $entry =~ /Port id:\s*(\S+)/i;
        ($nbr{mgmt_addr})   = $entry =~ /Management Addresses[^:]*:\s*\n\s*IP:\s*(\S+)/i;

        next unless ($nbr{system_name} || $nbr{chassis_id});
        $count++;
        output(sprintf("  [LLDP] %-30s  local:%-20s remote:%-20s ip:%s",
            $nbr{system_name} // $nbr{chassis_id} // 'unknown',
            $nbr{local_intf} // '?',
            $nbr{port_id} // '?',
            $nbr{mgmt_addr} // 'n/a'));
    }
    output("  [LLDP] No LLDP neighbors found.") if $count == 0;
}

sub output {
    my ($line) = @_;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}
```