```perl
#!/usr/bin/perl
#
# interface_errors.pl - Interface Error Counter Audit for Cisco IOS/IOS-XE
#
# PURPOSE:
#   Connects to Cisco network devices via SSH and audits interface error counters.
#   Flags interfaces exceeding configurable thresholds for CRC errors, input errors,
#   output drops, and resets. Useful for identifying degraded links, duplex mismatches,
#   and oversubscribed ports before they become outages.
#
# USAGE:
#   Single device:   ./interface_errors.pl -h 192.168.1.1 -u admin [-p password] [-l logfile]
#   From file:       ./interface_errors.pl -f devices.txt -u admin [-p password] [-l logfile]
#   With thresholds: ./interface_errors.pl -h 10.0.0.1 -u admin --crc 50 --drops 100
#
# PREREQUISITES:
#   Perl modules: Net::SSH::Expect, Getopt::Long, POSIX
#   Install: cpanm Net::SSH::Expect
#
# THRESHOLDS (defaults):
#   CRC errors      >= 10  (indicates physical layer issues, bad cable/SFP)
#   Input errors    >= 25  (frame errors, giants, runts)
#   Output drops    >= 50  (interface oversubscription/congestion)
#   Resets          >= 5   (interface flapping or keepalive failures)
#
# NOTES:
#   - Reads password from NETPASS env var if -p not provided (safer for scripting)
#   - Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x
#   - Use 'enable' password via NETENABLE env var if privilege escalation needed
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $device_file, $username, $password, $logfile);
my $crc_thresh   = 10;
my $err_thresh   = 25;
my $drop_thresh  = 50;
my $reset_thresh = 5;
my $timeout      = 15;

GetOptions(
    'h|host=s'    => \$host_arg,
    'f|file=s'    => \$device_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'l|log=s'     => \$logfile,
    'crc=i'       => \$crc_thresh,
    'errors=i'    => \$err_thresh,
    'drops=i'     => \$drop_thresh,
    'resets=i'    => \$reset_thresh,
) or die "Usage: $0 -h <host>|-f <file> -u <user> [-p <pass>] [-l <logfile>]\n";

die "Specify -h <host> or -f <file>\n" unless $host_arg || $device_file;
die "Specify -u <username>\n"           unless $username;

$password //= $ENV{NETPASS} or die "Provide password via -p or NETPASS env var\n";

my @devices = $host_arg ? ($host_arg) : do {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
};

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open logfile $logfile: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=" x 70);
output("Interface Error Audit  |  $timestamp");
output("Thresholds: CRC>=$crc_thresh  InputErr>=$err_thresh  Drops>=$drop_thresh  Resets>=$reset_thresh");
output("=" x 70);

for my $host (@devices) {
    audit_device($host);
}

close $log_fh if $log_fh;

sub audit_device {
    my ($host) = @_;
    output("\n[ $host ]");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $host,
            user        => $username,
            password    => $password,
            raw_pty     => 1,
            timeout     => $timeout,
        );
    };
    if ($@ || !$ssh) {
        output("  ERROR: Failed to create SSH session - $@");
        return;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !$login) {
        output("  ERROR: Authentication failed for $host");
        return;
    }

    # Disable paging and get interface counters
    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#|>', 5);
    $ssh->send("show interfaces");
    my $output = $ssh->waitfor('\$|#|>', $timeout) // '';

    $ssh->send("exit");
    $ssh->close();

    parse_and_report($host, $output);
}

sub parse_and_report {
    my ($host, $raw) = @_;
    my $found_issues = 0;
    my $current_intf = '';

    my (%crc, %input_err, %output_drop, %resets, %intf_line);

    for my $line (split /\n/, $raw) {
        if ($line =~ /^(\S+(?:Ethernet|Serial|Tunnel|Loopback|Vlan)\S*)\s+is\s+(\S+.*)/i) {
            $current_intf    = $1;
            $intf_line{$current_intf} = "  $1: $2";
        }
        next unless $current_intf;

        $crc{$current_intf}        = $1 if $line =~ /(\d+) CRC/;
        $input_err{$current_intf}  = $1 if $line =~ /(\d+) input errors/;
        $output_drop{$current_intf}= $1 if $line =~ /(\d+) output drops/;
        $resets{$current_intf}     = $1 if $line =~ /(\d+) interface resets/;
    }

    for my $intf (sort keys %intf_line) {
        my $c = $crc{$intf}         // 0;
        my $e = $input_err{$intf}   // 0;
        my $d = $output_drop{$intf} // 0;
        my $r = $resets{$intf}      // 0;

        next unless $c >= $crc_thresh || $e >= $err_thresh
                 || $d >= $drop_thresh || $r >= $reset_thresh;

        output($intf_line{$intf});
        output("    CRC=$c  InputErr=$e  OutputDrops=$d  Resets=$r");
        $found_issues = 1;
    }

    output("  No interfaces exceed thresholds.") unless $found_issues;
}

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}
```