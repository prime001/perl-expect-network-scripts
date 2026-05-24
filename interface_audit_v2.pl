```perl
#!/usr/bin/perl
# =============================================================================
# interface_errors.pl - Interface Error Counter Auditor
#
# Purpose:
#   SSH into Cisco IOS/IOS-XE devices and scan all interface error counters
#   (input errors, CRC, giants, runts, output drops). Reports non-zero counters
#   and flags interfaces where error rate exceeds a configurable threshold.
#   Useful for proactive fault detection, capacity planning, and pre-maintenance
#   baselining before circuit swaps or hardware replacements.
#
# Usage:
#   ./interface_errors.pl -h 192.168.1.1 -u admin -p secret
#   ./interface_errors.pl -f devices.txt -u admin -p secret -l audit.log
#   ./interface_errors.pl -h 10.0.0.1 -u admin -p secret -t 0.5
#
# Options:
#   -h  Device IP/hostname (or use -f for multiple)
#   -f  File with one device per line (# for comments)
#   -u  SSH username
#   -p  SSH password
#   -l  Log file path (appends; optional)
#   -t  Error rate % threshold to flag [WARN] (default: 1.0)
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $pass, $device_file, $log_file, $threshold);
$threshold = 1.0;

GetOptions(
    'h|host=s'      => \$host,
    'u|user=s'      => \$user,
    'p|pass=s'      => \$pass,
    'f|file=s'      => \$device_file,
    'l|log=s'       => \$log_file,
    't|threshold=f' => \$threshold,
) or die "Usage: $0 -h HOST -u USER -p PASS [-f FILE] [-l LOG] [-t THRESH%]\n";

die "ERROR: -u username required\n"        unless $user;
die "ERROR: -p password required\n"        unless $pass;
die "ERROR: specify -h HOST or -f FILE\n"  unless $host || $device_file;

my @devices;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if $_ }
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub out {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

for my $device (@devices) {
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    out("\n" . "=" x 65 . "\n");
    out("Host: $device   Scanned: $ts   Threshold: ${threshold}%\n");
    out("=" x 65 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $user,
        password => $pass,
        raw_pty  => 1,
        timeout  => 20,
    );

    eval { $ssh->login() };
    if ($@) {
        out("ERROR: Cannot connect to $device: $@\n");
        next;
    }

    $ssh->exec("terminal length 0");
    my $output = $ssh->exec("show interfaces");

    unless ($output) {
        out("ERROR: No output from $device — possible timeout or privilege issue\n");
        $ssh->close();
        next;
    }

    $ssh->close();

    my @results;
    my @blocks = split /\n(?=\S+\s+is\s+(?:up|down|administratively))/, $output;

    for my $block (@blocks) {
        my ($iface) = $block =~ /^(\S+)\s+is\s+/      or next;
        my ($state) = $block =~ /is\s+([\w\s]+?),/i   or next;
        $state =~ s/\s+$//;

        my ($in_pkts)  = ($block =~ /(\d+)\s+packets\s+input/i);
        my ($in_err)   = ($block =~ /(\d+)\s+input\s+errors/i);
        my ($crc)      = ($block =~ /(\d+)\s+CRC/i);
        my ($runts)    = ($block =~ /(\d+)\s+runts/i);
        my ($giants)   = ($block =~ /(\d+)\s+giants/i);
        my ($out_pkts) = ($block =~ /(\d+)\s+packets\s+output/i);
        my ($out_drop) = ($block =~ /(\d+)\s+output\s+drops/i);

        for ($in_pkts, $in_err, $crc, $runts, $giants, $out_pkts, $out_drop) {
            $_ //= 0;
        }

        my $total_err = $in_err + $crc + $runts + $giants + $out_drop;
        next if $total_err == 0;

        my $in_rate  = $in_pkts  > 0 ? ($in_err  / $in_pkts  * 100) : 0;
        my $out_rate = $out_pkts > 0 ? ($out_drop / $out_pkts * 100) : 0;
        my $max_rate = $in_rate > $out_rate ? $in_rate : $out_rate;
        my $flag     = $max_rate >= $threshold ? '[WARN]' : '';

        push @results, {
            iface    => $iface,
            state    => substr($state, 0, 8),
            in_err   => $in_err,
            crc      => $crc,
            runts    => $runts,
            giants   => $giants,
            out_drop => $out_drop,
            rate     => $max_rate,
            flag     => $flag,
        };
    }

    if (!@results) {
        out("All interfaces: zero error counters.\n");
        next;
    }

    @results = sort { ($b->{flag} cmp $a->{flag}) || ($b->{rate} <=> $a->{rate}) } @results;

    out(sprintf("%-26s %-8s %8s %8s %6s %6s %9s  %s\n",
        'Interface', 'State', 'InErr', 'CRC', 'Runts', 'Giants', 'OutDrop', 'Status'));
    out("-" x 82 . "\n");

    for my $r (@results) {
        out(sprintf("%-26s %-8s %8d %8d %6d %6d %9d  %s\n",
            $r->{iface}, $r->{state},
            $r->{in_err}, $r->{crc}, $r->{runts},
            $r->{giants}, $r->{out_drop}, $r->{flag}));
    }

    my $warn_count = grep { $_->{flag} } @results;
    out(sprintf("\nSummary: %d interface(s) with errors, %d exceed %.1f%% threshold\n",
        scalar @results, $warn_count, $threshold));
}

close $log_fh if $log_fh;
```