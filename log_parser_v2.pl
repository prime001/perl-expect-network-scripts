#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# syslog_event_monitor.pl - Network Device Syslog Event Analyzer
#
# Purpose:
#   SSH into Cisco IOS/IOS-XE devices and parse 'show logging' output to
#   detect and categorize critical syslog events: interface flaps, BGP state
#   changes, hardware errors, authentication failures, and CPU/memory alerts.
#   Generates a prioritized event summary useful for NOC triage and reporting.
#
# Usage:
#   ./syslog_event_monitor.pl --host <ip> --user <username> [options]
#   ./syslog_event_monitor.pl --file <hosts.txt> --user <username> [options]
#
# Options:
#   --host   <ip>       Single device IP or hostname
#   --file   <file>     File with one device IP/hostname per line
#   --user   <user>     SSH username
#   --pass   <pass>     SSH password (prompted if omitted)
#   --log    <file>     Write output to log file (default: syslog_events_YYYYMMDD.log)
#   --nolog             Disable log file output
#   --timeout <sec>     SSH timeout in seconds (default: 30)
#
# Prerequisites:
#   Net::SSH::Expect (cpan install Net::SSH::Expect)
#   SSH access to target devices, 'show logging' privilege
#
# Author: Network Engineering Team
# =============================================================================

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log, $opt_nolog, $opt_timeout);
$opt_timeout = 30;

GetOptions(
    'host=s'    => \$opt_host,
    'file=s'    => \$opt_file,
    'user=s'    => \$opt_user,
    'pass=s'    => \$opt_pass,
    'log=s'     => \$opt_log,
    'nolog'     => \$opt_nolog,
    'timeout=i' => \$opt_timeout,
) or die "Usage: $0 --host <ip> --user <user> [--pass <pass>] [--log <file>]\n";

die "ERROR: Specify --host or --file\n" unless $opt_host || $opt_file;
die "ERROR: --user is required\n" unless $opt_user;

unless ($opt_pass) {
    print "Password: ";
    system("stty -echo");
    chomp($opt_pass = <STDIN>);
    system("stty echo");
    print "\n";
}

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open(my $fh, '<', $opt_file) or die "Cannot open $opt_file: $!\n";
    @devices = grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
    close $fh;
}

my $logfile;
unless ($opt_nolog) {
    $opt_log ||= 'syslog_events_' . strftime('%Y%m%d_%H%M%S', localtime) . '.log';
    open($logfile, '>', $opt_log) or die "Cannot open log $opt_log: $!\n";
}

sub log_output {
    my $msg = shift;
    print $msg;
    print $logfile $msg if $logfile;
}

my %patterns = (
    FLAP       => qr/(?:UPDOWN|LINEPROTO-5-UPDOWN|LINK-3-UPDOWN)/,
    BGP        => qr/(?:BGP-5-ADJCHANGE|BGP.*(?:Up|Down|Reset))/,
    HARDWARE   => qr/(?:HARDWARE_ALARM|TRANSCEIVER|FAN|POWER|SYS-2-MALLOCFAIL)/,
    SECURITY   => qr/(?:SEC_LOGIN-4-LOGIN_FAILED|SSH-4-SSH2_UNEXPECTED_MSG|AAA.*fail)/i,
    CPU        => qr/(?:SYS-4-P2_WARN|CPUHOG|CPU.*exceed|PROC-4)/i,
    OSPF       => qr/(?:OSPF-5-ADJCHG|OSPF.*(?:FULL|INIT|DOWN))/,
);

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
log_output("=" x 70 . "\n");
log_output("Syslog Event Monitor Report - $timestamp\n");
log_output("=" x 70 . "\n\n");

for my $host (@devices) {
    log_output("Device: $host\n" . "-" x 40 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        user       => $opt_user,
        password   => $opt_pass,
        raw_pty    => 1,
        timeout    => $opt_timeout,
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output || $login_output =~ /[Pp]assword|[Dd]enied/) {
        log_output("  ERROR: Authentication failed or connection refused\n\n");
        next;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|\#|\>', 10);

    $ssh->send("show logging\n");
    my $output = '';
    eval {
        while (my $line = $ssh->read_line(5)) {
            last if $line =~ /\$|\#|\>/ && length($output) > 100;
            $output .= $line . "\n";
        }
    };

    $ssh->send("exit\n");

    my %events;
    for my $category (keys %patterns) {
        my @matches = grep { $_ =~ $patterns{$category} } split(/\n/, $output);
        $events{$category} = \@matches if @matches;
    }

    if (!%events) {
        log_output("  No critical events detected in syslog buffer.\n\n");
        next;
    }

    my $total = 0;
    for my $cat (sort keys %events) {
        my $count = scalar @{$events{$cat}};
        $total += $count;
        log_output(sprintf("  %-12s: %3d event(s)\n", $cat, $count));
        for my $line (@{$events{$cat}}[-3..-1]) {
            next unless defined $line;
            $line =~ s/^\s+//;
            log_output("    >> $line\n") if $line =~ /\S/;
        }
    }
    log_output("  Total events flagged: $total\n\n");
}

log_output("=" x 70 . "\n");
log_output("Report complete. Output: $opt_log\n") if $logfile;
close $logfile if $logfile;