```perl
#!/usr/bin/perl
# =============================================================================
# ntp_drift_monitor.pl - NTP Offset/Jitter Threshold Compliance Monitor
# =============================================================================
# Purpose:
#   Connects to network devices via SSH and checks NTP offset and jitter
#   values against configurable thresholds. Flags devices exceeding limits
#   and produces a compliance summary. Distinct from basic NTP sync checks —
#   this focuses on drift magnitude and jitter health for SLA compliance.
#
# Usage:
#   ./ntp_drift_monitor.pl -u <user> [-p <pass>] [-f <device_file>] [host ...]
#   ./ntp_drift_monitor.pl -u admin -f devices.txt
#   ./ntp_drift_monitor.pl -u admin 10.0.0.1 10.0.0.2
#
# Options:
#   -u  SSH username (required)
#   -p  SSH password (prompted if omitted)
#   -f  File with one device IP/hostname per line
#   -l  Log file path (default: ntp_drift_YYYYMMDD.log)
#   -o  Offset threshold in ms (default: 100)
#   -j  Jitter threshold in ms (default: 50)
#   -t  SSH timeout in seconds (default: 15)
#
# Prerequisites:
#   cpan Net::SSH::Expect Term::ReadKey
#   Devices must be IOS/IOS-XE (parses 'show ntp associations detail')
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);
use Term::ReadKey;

our %opts;
getopts('u:p:f:l:o:j:t:', \%opts);

my $username       = $opts{u} or die "Usage: $0 -u <user> [-p pass] [-f file] [hosts...]\n";
my $offset_thresh  = $opts{o} // 100;
my $jitter_thresh  = $opts{j} // 50;
my $timeout        = $opts{t} // 15;
my $datestamp      = strftime('%Y%m%d_%H%M%S', localtime);
my $logfile        = $opts{l} // "ntp_drift_$datestamp.log";

my $password;
if ($opts{p}) {
    $password = $opts{p};
} else {
    print "Password for $username: ";
    ReadMode('noecho');
    chomp($password = <STDIN>);
    ReadMode('restore');
    print "\n";
}

my @devices;
if ($opts{f}) {
    open(my $fh, '<', $opts{f}) or die "Cannot open device file '$opts{f}': $!\n";
    while (<$fh>) {
        chomp;
        s/#.*//;
        s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
}
push @devices, @ARGV;
die "No devices specified. Use -f <file> or list hosts as arguments.\n" unless @devices;

open(my $log, '>', $logfile) or die "Cannot open log '$logfile': $!\n";

sub log_print {
    my $msg = shift;
    print $msg;
    print $log $msg;
}

sub check_device {
    my ($host) = @_;
    my %result = (host => $host, status => 'ERROR', offset => 'N/A', jitter => 'N/A', ref_ip => 'N/A');

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $username,
        password    => $password,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    eval {
        my $login = $ssh->login();
        if ($login !~ /[>#]/) {
            die "Authentication failed or unexpected prompt";
        }

        $ssh->send("terminal length 0\n");
        $ssh->waitfor('[>#]', $timeout) or die "Prompt timeout after terminal length";

        $ssh->send("show ntp associations detail\n");
        my $output = '';
        my $chunk;
        while (defined($chunk = $ssh->read_all(3))) {
            $output .= $chunk;
            last if $output =~ /[>#]\s*$/;
        }

        $ssh->send("exit\n");
        $ssh->close();

        my ($offset, $jitter, $ref_ip);
        if ($output =~ /our\s+master,\s+stratum\s+\d+.*?ref\s+ID\s+([\d.]+)/si) {
            $ref_ip = $1;
        }
        if ($output =~ /offset\s+([-\d.]+)\s+msec/i) {
            $offset = $1;
        }
        if ($output =~ /jitter\s+([\d.]+)\s+msec/i) {
            $jitter = $1;
        }

        unless (defined $offset && defined $jitter) {
            $result{status} = 'NO_SYNC';
            return \%result;
        }

        $result{offset} = sprintf("%.3f", $offset);
        $result{jitter} = sprintf("%.3f", $jitter);
        $result{ref_ip} = $ref_ip // 'unknown';

        my $offset_abs = abs($offset);
        if ($offset_abs > $offset_thresh || $jitter > $jitter_thresh) {
            $result{status} = 'FAIL';
        } else {
            $result{status} = 'PASS';
        }
    };
    if ($@) {
        my $err = $@;
        $err =~ s/\n.*//s;
        $result{detail} = $err;
    }

    return \%result;
}

my $header = sprintf("\nNTP Drift Compliance Report — %s\n", strftime('%Y-%m-%d %H:%M:%S', localtime));
$header .= sprintf("Thresholds: offset=+/-%dms  jitter=%dms\n", $offset_thresh, $jitter_thresh);
$header .= sprintf("Devices: %d\n%s\n", scalar @devices, '-' x 72);
log_print($header);

my @results;
for my $host (@devices) {
    log_print(sprintf("Checking %-30s ... ", $host));
    my $r = check_device($host);
    push @results, $r;

    if ($r->{status} eq 'PASS') {
        log_print(sprintf("PASS  offset=%-10s jitter=%-10s ref=%s\n",
            "$r->{offset}ms", "$r->{jitter}ms", $r->{ref_ip}));
    } elsif ($r->{status} eq 'FAIL') {
        log_print(sprintf("FAIL  offset=%-10s jitter=%-10s ref=%s  *** EXCEEDS THRESHOLD\n",
            "$r->{offset}ms", "$r->{jitter}ms", $r->{ref_ip}));
    } elsif ($r->{status} eq 'NO_SYNC') {
        log_print("NO_SYNC  (not synchronized to any peer)\n");
    } else {
        log_print(sprintf("ERROR  %s\n", $r->{detail} // 'unknown error'));
    }
}

my @passed  = grep { $_->{status} eq 'PASS'    } @results;
my @failed  = grep { $_->{status} eq 'FAIL'    } @results;
my @nosync  = grep { $_->{status} eq 'NO_SYNC' } @results;
my @errors  = grep { $_->{status} eq 'ERROR'   } @results;

my $summary = sprintf("\n%s\nSUMMARY: %d PASS  %d FAIL  %d NO_SYNC  %d ERROR\n",
    '-' x 72, scalar @passed, scalar @failed, scalar @nosync, scalar @errors);
log_print($summary);

if (@failed) {
    log_print("\nDevices exceeding thresholds:\n");
    for my $r (@failed) {
        log_print(sprintf("  %-30s offset=%sms  jitter=%sms\n",
            $r->{host}, $r->{offset}, $r->{jitter}));
    }
}

log_print("\nLog saved to: $logfile\n");
close $log;

exit(@failed || @errors || @nosync ? 1 : 0);
```