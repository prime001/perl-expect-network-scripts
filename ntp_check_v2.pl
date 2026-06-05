Writing the script directly — the task is fully specified and needs no design iteration.

```
#!/usr/bin/perl
# =============================================================================
# ntp_drift_monitor.pl - NTP Drift and Stratum Quality Monitor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and evaluates NTP health
#   beyond basic sync status. Checks stratum depth, clock offset, jitter,
#   and reference source reachability. Produces threshold-based CRITICAL/
#   WARNING/OK verdicts suitable for feeding into monitoring pipelines.
#
# Usage:
#   Single device:   perl ntp_drift_monitor.pl -h 192.168.1.1 -u admin -p pass
#   Device file:     perl ntp_drift_monitor.pl -f hosts.txt -u admin -p pass
#   With log:        perl ntp_drift_monitor.pl -h 10.0.0.1 -u admin -p pass -l ntp.log
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   Device must have SSH enabled and NTP configured.
#   User requires privilege level sufficient for 'show ntp status' and
#   'show ntp associations'.
#
# Thresholds (adjust as needed):
#   Stratum > 4     => WARNING
#   Stratum > 8     => CRITICAL
#   Offset  > 50ms  => WARNING
#   Offset  > 500ms => CRITICAL
#   Jitter  > 100ms => WARNING
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);

my %opts;
getopts('h:f:u:p:l:t:', \%opts);

my $user    = $opts{u} or die "Usage: $0 -h host|-f file -u user -p pass [-l logfile] [-t timeout]\n";
my $pass    = $opts{p} or die "Password required (-p)\n";
my $timeout = $opts{t} || 15;
my $logfile = $opts{l};

my @devices;
if ($opts{f}) {
    open my $fh, '<', $opts{f} or die "Cannot open host file $opts{f}: $!\n";
    @devices = grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
    close $fh;
} elsif ($opts{h}) {
    @devices = ($opts{h});
} else {
    die "Specify -h <host> or -f <file>\n";
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!\n";
}

sub log_output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub check_device {
    my ($host) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $user,
        password     => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    eval { $ssh->login() };
    if ($@) {
        log_output("[$ts] CRITICAL $host: Connection/auth failed - $@\n");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$', 3);

    # Grab NTP status
    $ssh->send("show ntp status");
    my $status_out = $ssh->waitfor('\$', 10) // '';

    # Grab association detail for offset/jitter
    $ssh->send("show ntp associations");
    my $assoc_out = $ssh->waitfor('\$', 10) // '';

    $ssh->close();

    # Parse sync state
    my $synced = ($status_out =~ /Clock is synchronized/i) ? 1 : 0;
    my ($stratum) = $status_out =~ /stratum\s+(\d+)/i;
    my ($offset)  = $status_out =~ /offset\s+is\s+([\d.]+)/i;  # ms
    my ($ref_src) = $status_out =~ /reference is\s+(\S+)/i;

    # Parse best peer jitter from associations table
    my $jitter = undef;
    for my $line (split /\n/, $assoc_out) {
        if ($line =~ /^\*/) {  # * marks the selected peer
            my @f = split /\s+/, $line;
            $jitter = $f[-1] if @f >= 8;  # last field is jitter
        }
    }

    unless ($synced) {
        log_output("[$ts] CRITICAL $host: NTP not synchronized\n");
        return;
    }

    $stratum //= 99;
    $offset  //= 0;
    $jitter  //= 0;

    my @issues;
    my $severity = 'OK';

    if ($stratum > 8) {
        push @issues, "stratum=$stratum(CRITICAL)";
        $severity = 'CRITICAL';
    } elsif ($stratum > 4) {
        push @issues, "stratum=$stratum(WARN)";
        $severity = 'WARNING' if $severity eq 'OK';
    }

    if ($offset > 500) {
        push @issues, "offset=${offset}ms(CRITICAL)";
        $severity = 'CRITICAL';
    } elsif ($offset > 50) {
        push @issues, "offset=${offset}ms(WARN)";
        $severity = 'WARNING' if $severity eq 'OK';
    }

    if ($jitter > 100) {
        push @issues, "jitter=${jitter}ms(WARN)";
        $severity = 'WARNING' if $severity eq 'OK';
    }

    my $detail = @issues ? join(', ', @issues) : "stratum=$stratum offset=${offset}ms jitter=${jitter}ms";
    my $ref    = $ref_src ? " ref=$ref_src" : '';

    log_output("[$ts] $severity $host: $detail$ref\n");
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
log_output("[$ts] NTP drift monitor starting - " . scalar(@devices) . " device(s)\n");
log_output("-" x 72 . "\n");

check_device($_) for @devices;

log_output("-" x 72 . "\n");
log_output("[" . strftime('%Y-%m-%d %H:%M:%S', localtime) . "] Done\n");

close $log_fh if $log_fh;
```