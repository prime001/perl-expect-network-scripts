```perl
#!/usr/bin/perl
# =============================================================================
# syslog_analyzer.pl - Network Device Syslog Buffer Analyzer
# =============================================================================
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH, retrieves the syslog buffer
#   (show logging), and parses entries by severity level, facility, and time.
#   Produces a summary report highlighting critical/error conditions suitable
#   for NOC review or post-incident analysis.
#
# Usage:
#   Single device:  ./syslog_analyzer.pl -h 192.168.1.1 -u admin -p secret
#   Device list:    ./syslog_analyzer.pl -f devices.txt -u admin -p secret
#   With log file:  ./syslog_analyzer.pl -h 192.168.1.1 -u admin -p secret -o report.log
#   Filter severity:./syslog_analyzer.pl -h 192.168.1.1 -u admin -p secret -s 3
#
# Options:
#   -h <host>      Target device IP or hostname
#   -f <file>      File containing one device IP/hostname per line
#   -u <user>      SSH username
#   -p <pass>      SSH password (prompted if omitted)
#   -e <enable>    Enable password (optional)
#   -o <file>      Output log file (default: syslog_report_YYYYMMDD.log)
#   -s <level>     Minimum severity to report (0=emerg..7=debug, default 4)
#   -n <count>     Max log lines to retrieve (default 500)
#
# Prerequisites:
#   cpan Net::SSH::Expect Term::ReadKey
#
# Tested on: Cisco IOS 15.x, IOS-XE 16.x/17.x
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);
use Term::ReadKey;

our %opts;
getopts('h:f:u:p:e:o:s:n:', \%opts);

my $username    = $opts{u} or die "Usage: $0 -h <host>|-f <file> -u <user> [-p pass] [-e enable] [-o logfile] [-s severity] [-n lines]\n";
my $password    = $opts{p} || prompt_password("SSH password for $username: ");
my $enable_pass = $opts{e} || '';
my $min_sev     = defined $opts{s} ? $opts{s} : 4;
my $max_lines   = $opts{n} || 500;
my $datestamp   = strftime("%Y%m%d_%H%M%S", localtime);
my $logfile     = $opts{o} || "syslog_report_${datestamp}.log";

my @severity_names = qw(EMERGENCY ALERT CRITICAL ERROR WARNING NOTICE INFORMATIONAL DEBUG);

my @devices;
if ($opts{h}) {
    push @devices, $opts{h};
} elsif ($opts{f}) {
    open my $fh, '<', $opts{f} or die "Cannot open device file $opts{f}: $!";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^#/;
        push @devices, $_;
    }
    close $fh;
} else {
    die "Specify -h <host> or -f <file>\n";
}

open my $LOG, '>', $logfile or die "Cannot open log file $logfile: $!";

output($LOG, "=" x 70);
output($LOG, "Syslog Buffer Analysis Report");
output($LOG, "Generated: " . strftime("%Y-%m-%d %H:%M:%S", localtime));
output($LOG, "Minimum severity reported: $min_sev ($severity_names[$min_sev])");
output($LOG, "=" x 70 . "\n");

for my $host (@devices) {
    analyze_device($host, $username, $password, $enable_pass, $min_sev, $max_lines, $LOG);
}

close $LOG;
print "\nReport written to: $logfile\n";

# -----------------------------------------------------------------------------
sub analyze_device {
    my ($host, $user, $pass, $enable, $min_sev, $max_lines, $log) = @_;

    output($log, "\n" . "-" x 70);
    output($log, "Device: $host");
    output($log, "-" x 70);

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host        => $host,
            user        => $user,
            password    => $pass,
            raw_pty     => 1,
            timeout     => 20,
        );
        $ssh->login();
    };
    if ($@ || !$ssh) {
        output($log, "ERROR: Connection failed to $host: $@");
        return;
    }

    # Enter enable mode if password provided
    if ($enable) {
        $ssh->send("enable");
        my $result = $ssh->waitfor('Password:', 10);
        if ($result) {
            $ssh->send($enable);
            $ssh->waitfor('[#>]', 10);
        }
    }

    # Disable paging and get hostname
    $ssh->exec("terminal length 0");
    my $hostname_out = $ssh->exec("show version | include uptime");
    my $hostname = ($hostname_out =~ /^(\S+)\s+uptime/m) ? $1 : $host;

    output($log, "Hostname: $hostname");

    # Retrieve syslog buffer
    my $log_output = $ssh->exec("show logging | tail $max_lines");
    unless ($log_output) {
        $log_output = $ssh->exec("show logging");
    }

    $ssh->close();

    # Parse logging configuration header
    if ($log_output =~ /Syslog logging:\s*(\S+)/i) {
        output($log, "Syslog state: $1");
    }
    if ($log_output =~ /Buffer logging:\s*level (\w+),\s*(\d+) messages logged/i) {
        output($log, "Buffer level: $1, Messages logged: $2");
    }

    # Parse individual log entries
    # Cisco format: *Apr  8 14:23:01.456: %FACILITY-SEV-MNEMONIC: message
    my %sev_counts = map { $_ => 0 } 0..7;
    my @flagged;

    while ($log_output =~ /^[*.]?(\w+\s+\d+\s+[\d:]+(?:\.\d+)?(?:\s+\w+)?):?\s+%(\w+)-(\d)-(\w+):\s+(.+)$/mg) {
        my ($timestamp, $facility, $severity, $mnemonic, $message) = ($1, $2, $3, $4, $5);
        $sev_counts{$severity}++ if exists $sev_counts{$severity};
        if ($severity <= $min_sev) {
            push @flagged, {
                ts       => $timestamp,
                facility => $facility,
                sev      => $severity,
                mnemonic => $mnemonic,
                msg      => $message,
            };
        }
    }

    # Summary table
    output($log, "\nSeverity Distribution:");
    for my $s (0..7) {
        next unless $sev_counts{$s};
        my $marker = ($s <= 3) ? " <-- ATTENTION" : "";
        output($log, sprintf("  %-15s (%-2d): %d entries%s", $severity_names[$s], $s, $sev_counts{$s}, $marker));
    }

    # Flagged entries
    if (@flagged) {
        output($log, "\nFlagged Entries (severity <= $min_sev):");
        for my $entry (sort { $a->{sev} <=> $b->{sev} } @flagged) {
            output($log, sprintf("  [%s] %-8s %s-%d-%s: %s",
                $entry->{ts}, $entry->{facility}, $entry->{facility},
                $entry->{sev}, $entry->{mnemonic}, $entry->{msg}));
        }
    } else {
        output($log, "\nNo entries found at or below severity $min_sev ($severity_names[$min_sev]).");
    }
}

sub output {
    my ($fh, $msg) = @_;
    print "$msg\n";
    print $fh "$msg\n";
}

sub prompt_password {
    my ($prompt) = @_;
    print $prompt;
    ReadMode('noecho');
    my $pw = ReadLine(0);
    ReadMode('restore');
    chomp $pw;
    print "\n";
    return $pw;
}
```