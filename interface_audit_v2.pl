I'll write a CDP/LLDP neighbor discovery script — distinct from the existing interface audit, inventory collection, and show_commands scripts already in the repo.

```perl
#!/usr/bin/perl
# cdp_lldp_neighbors.pl - CDP/LLDP neighbor discovery and topology mapping
#
# PURPOSE:
#   Connects to Cisco IOS/IOS-XE/NX-OS devices via SSH and collects CDP and
#   LLDP neighbor tables for topology documentation, cabling verification, and
#   unauthorized device detection. Output is pipe-delimited for easy import
#   into spreadsheets or CMDB tools.
#
# USAGE:
#   Single device:  ./cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin [-p pass] [-l out.log]
#   Device list:    ./cdp_lldp_neighbors.pl -f devices.txt  -u admin [-p pass] [-l out.log]
#
# OUTPUT FORMAT:
#   PROTO|LOCAL_DEVICE|LOCAL_PORT|NEIGHBOR_ID|NEIGHBOR_PORT|PLATFORM|MGMT_IP
#
# PREREQUISITES:
#   cpan install Net::SSH::Expect

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_logfile, $opt_help);
my $TIMEOUT = 20;

GetOptions(
    'h|host=s' => \$opt_host,
    'f|file=s' => \$opt_file,
    'u|user=s' => \$opt_user,
    'p|pass=s' => \$opt_pass,
    'l|log=s'  => \$opt_logfile,
    'help'     => \$opt_help,
) or usage();

usage() if $opt_help || (!$opt_host && !$opt_file) || !$opt_user;

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open(my $fh, '<', $opt_file) or die "Cannot open '$opt_file': $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if length }
    close $fh;
}

my $log_fh;
if ($opt_logfile) {
    open($log_fh, '>', $opt_logfile) or die "Cannot open log '$opt_logfile': $!\n";
    printf $log_fh "# CDP/LLDP Neighbor Report generated %s\n", strftime("%Y-%m-%d %H:%M:%S", localtime);
    print  $log_fh "# PROTO|LOCAL_DEVICE|LOCAL_PORT|NEIGHBOR_ID|NEIGHBOR_PORT|PLATFORM|MGMT_IP\n";
}

sub out {
    my ($line) = @_;
    print $line;
    print $log_fh $line if $log_fh;
}

for my $device (@devices) {
    audit_device($device);
}
close $log_fh if $log_fh;

sub audit_device {
    my ($target) = @_;

    my $ssh = Net::SSH::Expect->new(
        host     => $target,
        user     => $opt_user,
        $opt_pass ? (password => $opt_pass) : (),
        raw_pty  => 1,
        timeout  => $TIMEOUT,
    );

    my $login;
    eval { $login = $ssh->login() };
    if ($@ || !defined $login) {
        out("ERROR|$target|||||||connection failed\n");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('[\$#>]', 5);

    my $hostname = $target;
    $ssh->send("show version | include uptime");
    my $ver = $ssh->waitfor('[\$#>]', 10) // '';
    $hostname = $1 if $ver =~ /^(\S+)\s+uptime/m;

    $ssh->send("show cdp neighbors detail");
    my $cdp = $ssh->waitfor('[\$#>]', $TIMEOUT) // '';
    parse_cdp($hostname, $cdp);

    $ssh->send("show lldp neighbors detail");
    my $lldp = $ssh->waitfor('[\$#>]', $TIMEOUT) // '';
    parse_lldp($hostname, $lldp) unless $lldp =~ /invalid|% LLDP is not enabled|error/i;

    $ssh->close();
}

sub parse_cdp {
    my ($device, $raw) = @_;
    my @blocks = split /[-]{4,}/, $raw;
    for my $b (@blocks) {
        next unless $b =~ /Device ID/i;
        my ($nbr)   = $b =~ /Device ID:\s*(\S+)/i;
        my ($lport) = $b =~ /Interface:\s*(\S+),/i;
        my ($rport) = $b =~ /Port ID[^:]*:\s*(\S+)/i;
        my ($plat)  = $b =~ /Platform:\s*([^,\n]+)/i;
        my ($mgmt)  = $b =~ /IP(?:v4)? [Aa]ddress:\s*(\d[\d.]+)/;
        $_ //= 'unknown' for $nbr, $lport, $rport, $plat, $mgmt;
        s/^\s+|\s+$//g for $plat;
        out("CDP|$device|$lport|$nbr|$rport|$plat|$mgmt\n");
    }
}

sub parse_lldp {
    my ($device, $raw) = @_;
    my @blocks = split /(?=Local Intf)/i, $raw;
    for my $b (@blocks) {
        next unless $b =~ /System Name/i;
        my ($lport) = $b =~ /Local Intf[^:]*:\s*(\S+)/i;
        my ($nbr)   = $b =~ /System Name[^:]*:\s*(\S+)/i;
        my ($rport) = $b =~ /Port (?:id|desc)[^:]*:\s*(\S+)/i;
        my ($plat)  = $b =~ /System Description[^:]*:\s*([^\n]+)/i;
        my ($mgmt)  = $b =~ /(\d{1,3}(?:\.\d{1,3}){3})/;
        $_ //= 'unknown' for $nbr, $lport, $rport, $plat, $mgmt;
        s/^\s+|\s+$//g for $plat;
        out("LLDP|$device|$lport|$nbr|$rport|$plat|$mgmt\n");
    }
}

sub usage {
    die "Usage: $0 -h HOST|-f FILE -u USER [-p PASS] [-l LOGFILE]\n";
}
```