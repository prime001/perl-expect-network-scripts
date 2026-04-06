#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# 008_hardware_inventory.pl - Network Device Hardware Inventory Collector
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and collects hardware
#   inventory data: hostname, platform model, serial number(s), IOS version,
#   DRAM/flash capacity, and uptime. Outputs a CSV-friendly summary suitable
#   for import into spreadsheets or asset management systems.
#
#   Targets "show version" and "show inventory" — two commands that together
#   give a complete hardware fingerprint without requiring enable privileges.
#
# Usage:
#   Single device:    ./008_hardware_inventory.pl -h 192.168.1.1
#   Device list:      ./008_hardware_inventory.pl -f devices.txt
#   CSV output:       ./008_hardware_inventory.pl -f devices.txt -o inv.csv
#   Custom creds:     ./008_hardware_inventory.pl -h 10.0.0.1 -u netops -p s3cr3t
#
# Prerequisites:
#   - Perl modules: Net::SSH::Expect, Getopt::Long (cpan install Net::SSH::Expect)
#   - SSH access to target devices (key-based or password)
#   - Credentials via -u/-p flags or NET_USER/NET_PASS environment variables
#   - Tested against Cisco IOS 12.4+, IOS-XE 3.x/16.x/17.x
#
# Output columns (CSV):
#   timestamp, device, hostname, platform, chassis_serial, ios_version,
#   dram_mb, flash_mb, uptime
# =============================================================================

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_out, $opt_timeout);
$opt_timeout = 30;

GetOptions(
    'h|host=s'    => \$opt_host,
    'f|file=s'    => \$opt_file,
    'u|user=s'    => \$opt_user,
    'p|pass=s'    => \$opt_pass,
    'o|output=s'  => \$opt_out,
    't|timeout=i' => \$opt_timeout,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-o outfile]\n";

die "Specify -h <host> or -f <file>\n" unless $opt_host || $opt_file;

my $username = $opt_user || $ENV{NET_USER} || 'admin';
my $password = $opt_pass || $ENV{NET_PASS} || die "No password: use -p or NET_PASS env\n";

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open(my $fh, '<', $opt_file) or die "Cannot open $opt_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^#/;
        push @devices, $_;
    }
    close $fh;
}

my $out_fh;
my $csv_header = "timestamp,device,hostname,platform,chassis_serial,ios_version,dram_mb,flash_mb,uptime\n";
if ($opt_out) {
    open($out_fh, '>', $opt_out) or die "Cannot open $opt_out: $!\n";
    print $out_fh $csv_header;
}
print $csv_header;

for my $device (@devices) {
    my $ts = strftime("%Y-%m-%dT%H:%M:%S", localtime);
    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $username,
        password     => $password,
        raw_pty     => 1,
        timeout     => $opt_timeout,
    );

    my $login_out = eval { $ssh->login() };
    if ($@ || !defined $login_out) {
        warn "[$device] SSH login failed: $@\n";
        my $row = "$ts,$device,ERROR,,,,,, login_failed\n";
        print $row;
        print $out_fh $row if $out_fh;
        next;
    }

    # Disable paging so we get full output without --More-- prompts
    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#|>', 5);

    # Collect show version
    $ssh->send("show version");
    my $ver_out = $ssh->waitfor('\$|#|>', $opt_timeout) // '';

    # Collect show inventory
    $ssh->send("show inventory");
    my $inv_out = $ssh->waitfor('\$|#|>', $opt_timeout) // '';

    $ssh->close();

    # --- Parse show version ---
    my ($hostname, $ios_ver, $platform, $dram, $flash, $uptime) = ('','','','','','');

    ($hostname)  = $ver_out =~ /^(\S+)\s+uptime/m;
    ($ios_ver)   = $ver_out =~ /Cisco IOS.*?Version\s+(\S+)/;
    ($ios_ver) //= '';
    $ios_ver     =~ s/,$//;

    ($platform)  = $ver_out =~ /^[Cc]isco\s+(\S+)\s+.*?processor/m;
    ($platform) //= '';

    ($dram)      = $ver_out =~ /(\d+)[KkMm] bytes of (?:physical memory|main memory|processor board)/;
    if (defined $dram) {
        $dram = ($ver_out =~ /\d+K bytes/ && $dram =~ /^\d+$/) ? int($dram/1024) : $dram;
    }
    $dram //= '';

    ($flash)     = $ver_out =~ /(\d+)[KkMm] bytes of.*?[Ff]lash/;
    if (defined $flash) {
        $flash = ($ver_out =~ /\d+K bytes.*?[Ff]lash/ && $flash =~ /^\d+$/) ? int($flash/1024) : $flash;
    }
    $flash //= '';

    ($uptime)    = $ver_out =~ /uptime is (.+)/;
    $uptime    //= '';
    $uptime      =~ s/\s+/ /g;
    $uptime      =~ s/,//g;

    # --- Parse show inventory for chassis serial ---
    my $chassis_serial = '';
    if ($inv_out =~ /NAME:\s+"Chassis".*?SN:\s*(\S+)/s) {
        $chassis_serial = $1;
    } elsif ($inv_out =~ /SN:\s*(\S+)/) {
        $chassis_serial = $1;
    }

    # Sanitize for CSV (quote uptime field which contains spaces/commas)
    my $row = sprintf('%s,%s,%s,%s,%s,%s,%s,%s,"%s"' . "\n",
        $ts, $device,
        $hostname     // '',
        $platform     // '',
        $chassis_serial,
        $ios_ver      // '',
        $dram         // '',
        $flash        // '',
        $uptime       // '',
    );

    print $row;
    print $out_fh $row if $out_fh;
}

close $out_fh if $out_fh;