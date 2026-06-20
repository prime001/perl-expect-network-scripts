#!/usr/bin/perl
#
# device_cdp_neighbor_audit.pl
#
# Purpose: Audit CDP neighbor topology on network devices to verify expected physical connectivity
#
# Usage:
#   perl device_cdp_neighbor_audit.pl <device_ip> <username> <password>
#   perl device_cdp_neighbor_audit.pl -f devices.txt -u username -p password [-l audit.log]
#
# Prerequisites:
#   - Net::SSH::Expect module installed
#   - SSH access to Cisco IOS/IOS-XE devices with CDP enabled
#   - Credentials with read access (enable mode optional)
#
# Description:
#   Collects and reports CDP neighbor information including device ID, local/remote ports,
#   and platform details. Useful for physical topology validation and cabling audits.

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Localtime;

my ($device_file, $username, $password, $logfile);
my $log_fh;

GetOptions(
    'f|file=s' => \$device_file,
    'u|user=s' => \$username,
    'p|pass=s' => \$password,
    'l|log=s'  => \$logfile,
) or die "Error in command line arguments\n";

my @devices;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open device file: $!\n";
    chomp(@devices = grep { $_ && $_ !~ /^#/ } <$fh>);
    close $fh;
} else {
    my $device = shift @ARGV;
    die "Usage: $0 <device> <user> <pass> or $0 -f devices.txt -u user -p pass [-l logfile]\n"
        unless $device;
    @devices = ($device);
    $username ||= shift @ARGV;
    $password ||= shift @ARGV;
}

die "Username and password required\n" unless $username && $password;

if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log file: $!\n";
}

foreach my $device (@devices) {
    audit_cdp_neighbors($device, $username, $password);
}
close $log_fh if $log_fh;

sub audit_cdp_neighbors {
    my ($host, $user, $pass) = @_;
    my $ts = scalar localtime;
    output_log("[$ts] Starting CDP audit for $host");

    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        user       => $user,
        password   => $pass,
        timeout    => 15,
        raw_pty    => 1,
    );

    unless ($ssh->connect()) {
        output_log("[ERROR] Cannot connect to $host: " . $ssh->error);
        return;
    }

    eval {
        $ssh->waitfor('.*[#>]', 5) or die "CLI prompt timeout\n";
        $ssh->send('terminal length 0');
        $ssh->waitfor('.*[#>]', 2);

        my $output = '';
        $ssh->send('show cdp neighbors detail');
        while (my $line = $ssh->read_line()) {
            last if $line =~ /^[a-zA-Z0-9\-#>]/;
            $output .= $line . "\n";
        }

        $ssh->send('show cdp neighbors');
        my $summary = '';
        while (my $line = $ssh->read_line()) {
            last if $line =~ /^[a-zA-Z0-9\-#>]/;
            $summary .= $line . "\n";
        }

        parse_and_report_cdp($host, $output, $summary);
        $ssh->send('exit');
        $ssh->close();
    };

    if ($@) {
        output_log("[ERROR] $host - Command execution failed: $@");
    }
}

sub parse_and_report_cdp {
    my ($host, $detail, $summary) = @_;
    my @neighbors = split /^-+$/m, $detail;
    shift @neighbors;

    my $count = scalar @neighbors;
    output_log("[INFO] $host has $count CDP neighbor(s)");

    foreach my $neighbor (@neighbors) {
        if ($neighbor =~ /Device ID: (.+?)$/m) {
            my $device_id = $1;
            my $platform = $neighbor =~ /Platform: (.+?)$/m ? $1 : "unknown";
            my $local_port = $neighbor =~ /Interface: (.+?),/m ? $1 : "unknown";
            my $remote_port = $neighbor =~ /outgoing port ID \(.*?\): (.+?)$/m ? $1 : "unknown";

            my $msg = sprintf(
                "[CDP] %s: %s (Platform: %s) | Local: %s -> Remote: %s",
                $host, $device_id, $platform, $local_port, $remote_port
            );
            output_log($msg);
        }
    }
}

sub output_log {
    my ($msg) = @_;
    print "$msg\n";
    if ($log_fh) {
        print $log_fh "$msg\n";
    }
}