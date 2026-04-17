#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# interface_errors.pl - Interface Error Counter Audit
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and audits interface error
#   counters (CRC, input errors, output drops, resets, runts, giants).
#   Flags any interface exceeding configurable thresholds — useful for
#   identifying degraded cables, duplex mismatches, or overloaded uplinks
#   before they impact production traffic.
#
# Usage:
#   ./interface_errors.pl -h <host> [-u <user>] [-p <pass>] [-l <logfile>]
#                         [-t <threshold>] [-f <device_list>]
#
# Prerequisites:
#   cpan Net::SSH::Expect
#
# Examples:
#   ./interface_errors.pl -h 192.168.1.1 -u admin -p secret
#   ./interface_errors.pl -f devices.txt -t 100 -l /var/log/if_errors.log
# =============================================================================

my ($host, $username, $password, $logfile, $device_file);
my $threshold = 50;   # flag interfaces with errors above this count

GetOptions(
    'h|host=s'      => \$host,
    'u|user=s'      => \$username,
    'p|pass=s'      => \$password,
    'l|log=s'       => \$logfile,
    't|threshold=i' => \$threshold,
    'f|file=s'      => \$device_file,
) or die "Usage: $0 -h <host> [-u user] [-p pass] [-l logfile] [-t threshold] [-f device_list]\n";

$username //= $ENV{NET_USER} // 'admin';
$password //= $ENV{NET_PASS} or die "ERROR: Password required via -p or NET_PASS env var\n";

my @hosts;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open device file '$device_file': $!\n";
    while (<$fh>) { chomp; push @hosts, $_ if /\S/ && !/^#/; }
    close $fh;
} elsif ($host) {
    @hosts = ($host);
} else {
    die "ERROR: Specify -h <host> or -f <device_list>\n";
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open logfile '$logfile': $!\n";
}

sub log_print {
    my ($msg) = @_;
    print $msg;
    print {$log_fh} $msg if $log_fh;
}

sub audit_device {
    my ($device) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);

    log_print("\n[$ts] === Connecting to $device ===\n");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host        => $device,
            user        => $username,
            password    => $password,
            raw_pty     => 1,
            timeout     => 15,
        );
        $ssh->login();
    };
    if ($@) {
        log_print("ERROR: Cannot connect to $device: $@\n");
        return;
    }

    # Disable paging
    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|#', 5);

    $ssh->send("show interfaces\n");
    my $output = $ssh->waitfor('#', 30) // '';

    if (!$output) {
        log_print("ERROR: No response from $device\n");
        $ssh->close();
        return;
    }

    my %iface_errors;
    my $current_if = '';

    for my $line (split /\n/, $output) {
        # Match interface header line
        if ($line =~ /^(\S+)\s+is\s+(up|down|administratively down)/) {
            $current_if = $1;
            $iface_errors{$current_if} //= { crc => 0, input_err => 0, output_drop => 0, resets => 0, runts => 0, giants => 0 };
            next;
        }
        next unless $current_if;

        if ($line =~ /(\d+)\s+input errors.*?(\d+)\s+CRC/) {
            $iface_errors{$current_if}{input_err} = $1;
            $iface_errors{$current_if}{crc}       = $2;
        }
        if ($line =~ /(\d+)\s+output drops/) {
            $iface_errors{$current_if}{output_drop} = $1;
        }
        if ($line =~ /(\d+)\s+interface resets/) {
            $iface_errors{$current_if}{resets} = $1;
        }
        if ($line =~ /(\d+)\s+runts,\s+(\d+)\s+giants/) {
            $iface_errors{$current_if}{runts}  = $1;
            $iface_errors{$current_if}{giants} = $2;
        }
    }

    $ssh->send("show version | include uptime\n");
    my $uptime_raw = $ssh->waitfor('#', 10) // '';
    my $uptime = ($uptime_raw =~ /uptime is (.+)/i) ? $1 : 'unknown';
    $uptime =~ s/\r//g;

    $ssh->send("exit\n");
    $ssh->close();

    log_print("Device uptime: $uptime\n");
    log_print(sprintf("%-30s %8s %8s %10s %8s %8s %8s\n",
        'Interface', 'CRC', 'InpErr', 'OutDrop', 'Resets', 'Runts', 'Giants'));
    log_print('-' x 82 . "\n");

    my $flagged = 0;
    for my $iface (sort keys %iface_errors) {
        my $e = $iface_errors{$iface};
        my $total = $e->{crc} + $e->{input_err} + $e->{output_drop}
                  + $e->{resets} + $e->{runts} + $e->{giants};
        next if $total == 0 && !($iface =~ /^(Gi|Fa|Te|Hu|Et)/i);

        my $flag = ($total > $threshold) ? ' *** EXCEEDS THRESHOLD' : '';
        log_print(sprintf("%-30s %8d %8d %10d %8d %8d %8d%s\n",
            $iface, $e->{crc}, $e->{input_err}, $e->{output_drop},
            $e->{resets}, $e->{runts}, $e->{giants}, $flag));
        $flagged++ if $flag;
    }

    log_print("\nSummary: $flagged interface(s) exceed error threshold of $threshold on $device\n");
}

audit_device($_) for @hosts;
close $log_fh if $log_fh;