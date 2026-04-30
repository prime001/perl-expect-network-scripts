#!/usr/bin/perl
use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# bgp_route_monitor.pl - BGP Prefix Count Monitor with Threshold Alerting
#
# Purpose:
#   Connects to IOS/IOS-XE routers via SSH and checks BGP peer prefix counts
#   against configurable thresholds. Flags peers with anomalous route counts
#   (too few suggesting a filter problem, too many suggesting a route leak).
#   Useful for capacity planning audits and change-window pre/post checks.
#
# Usage:
#   Single device:  perl bgp_route_monitor.pl -h 10.0.0.1 -u admin -p secret
#   Device file:    perl bgp_route_monitor.pl -f devices.txt -u admin -p secret
#   With logging:   perl bgp_route_monitor.pl -h 10.0.0.1 -u admin -p secret -l bgp_audit.log
#   Set thresholds: perl bgp_route_monitor.pl -h 10.0.0.1 -u admin -p secret --min 100 --max 900000
#
# Device file format (one entry per line):
#   10.0.0.1
#   router2.example.com
#
# Prerequisites:
#   - Perl modules: Expect, Getopt::Long (cpan install Expect)
#   - SSH key-based auth recommended; password auth supported via -p flag
#   - Router must have 'ip ssh' enabled and user with appropriate privilege
#
# Output:
#   Prints per-peer prefix counts with WARN/ALERT flags to STDOUT and log file.
# =============================================================================

my ($host, $username, $password, $device_file, $log_file);
my $min_prefixes = 1;
my $max_prefixes = 750000;
my $timeout      = 30;

GetOptions(
    'h|host=s'     => \$host,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'f|file=s'     => \$device_file,
    'l|log=s'      => \$log_file,
    'min=i'        => \$min_prefixes,
    'max=i'        => \$max_prefixes,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> -u <user> [-p <pass>] [-l <logfile>] [--min N] [--max N]\n";

die "Specify -h <host> or -f <file>\n" unless $host || $device_file;
die "Username required (-u)\n"         unless $username;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; push @devices, $_ if /\S/ && !/^#/ }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

sub log_print {
    my ($msg) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    print "[$ts] $msg\n";
    print $log_fh "[$ts] $msg\n" if $log_fh;
}

sub audit_device {
    my ($device) = @_;

    log_print("Connecting to $device ...");

    my @cmd = ('ssh', '-o', 'StrictHostKeyChecking=no',
                      '-o', 'ConnectTimeout=10',
                      "$username\@$device");

    my $exp = Expect->new;
    $exp->raw_pty(1);
    $exp->log_stdout(0);
    $exp->spawn(@cmd) or do { log_print("ERROR: Cannot spawn SSH for $device: $!"); return };

    my $authed = 0;
    $exp->expect($timeout,
        [ qr/[Pp]assword[:\s]/,         sub { $exp->send("$password\r"); exp_continue } ],
        [ qr/[#>]\s*$/,                 sub { $authed = 1 } ],
        [ qr/Connection refused/,       sub { log_print("ERROR: SSH refused on $device") } ],
        [ qr/No route to host/,         sub { log_print("ERROR: No route to $device") } ],
        [ qr/Host key verification/,    sub { log_print("ERROR: Host key mismatch on $device") } ],
        [ timeout => sub { log_print("ERROR: Timeout connecting to $device") } ],
    );

    unless ($authed) {
        $exp->soft_close;
        return;
    }

    $exp->send("terminal length 0\r");
    $exp->expect($timeout, qr/[#>]\s*$/);

    $exp->send("show ip bgp summary\r");
    my $summary = '';
    $exp->expect($timeout,
        [ qr/[#>]\s*$/m, sub { $summary = $exp->before() . $exp->match() } ],
        [ timeout        => sub { log_print("WARN: Timeout on bgp summary from $device") } ],
    );

    unless ($summary) {
        log_print("WARN: No BGP summary output from $device");
        $exp->send("exit\r");
        $exp->soft_close;
        return;
    }

    log_print("--- BGP Prefix Audit: $device ---");

    my @peers;
    for my $line (split /\n/, $summary) {
        # IOS bgp summary peer lines: IP state/up-time PfxRcd
        if ($line =~ /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\d+|NoNeg|Active|Idle|Connect)\s*$/) {
            push @peers, { ip => $1, pfx => $2 };
        }
    }

    unless (@peers) {
        log_print("  No established BGP peers found on $device");
        $exp->send("exit\r");
        $exp->soft_close;
        return;
    }

    for my $peer (@peers) {
        my $ip  = $peer->{ip};
        my $pfx = $peer->{pfx};

        if ($pfx =~ /^\d+$/) {
            my $flag = '';
            $flag = ' [WARN: below minimum]' if $pfx < $min_prefixes;
            $flag = ' [ALERT: exceeds maximum - possible route leak!]' if $pfx > $max_prefixes;
            log_print(sprintf("  Peer %-18s  PfxRcd: %7d%s", $ip, $pfx, $flag));
        } else {
            log_print(sprintf("  Peer %-18s  State: %s [not established]", $ip, $pfx));
        }
    }

    $exp->send("exit\r");
    $exp->soft_close;
}

log_print("BGP route monitor started — min=$min_prefixes max=$max_prefixes");
audit_device($_) for @devices;
log_print("BGP route monitor complete.");
close $log_fh if $log_fh;