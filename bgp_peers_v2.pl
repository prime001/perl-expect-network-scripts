#!/usr/bin/perl
#
# bgp_route_dampening.pl - BGP Route Dampening and Flap Statistics Monitor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers via SSH and reports on BGP route
#   dampening status: suppressed prefixes, active flap counts, penalty values,
#   and configured half-life/reuse thresholds. Useful for diagnosing route
#   instability events and confirming dampening policy is operational.
#
# Usage:
#   ./bgp_route_dampening.pl -h <host> [-u <user>] [-p <pass>] [-l <logfile>]
#   ./bgp_route_dampening.pl -f <file>  [-u <user>] [-p <pass>] [-l <logfile>]
#
# Prerequisites:
#   cpan Expect Getopt::Long
#   SSH reachability with at least read-only (show) access
#   Perl 5.10+
#
# Environment:
#   NET_USER, NET_PASS — fallback credentials if -u/-p not supplied
#

use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $logfile, $timeout, $help);
$user    = $ENV{NET_USER} // 'admin';
$pass    = $ENV{NET_PASS} // '';
$timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$file,
    'u|user=s'    => \$user,
    'p|pass=s'    => \$pass,
    'l|log=s'     => \$logfile,
    't|timeout=i' => \$timeout,
    'help'        => \$help,
) or usage();

usage() if $help || (!$host && !$file);

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    while (<$fh>) { chomp; next if /^\s*[#;]/ || /^\s*$/; push @devices, $_; }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!\n";
    $log_fh->autoflush(1);
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);

for my $device (@devices) {
    out("", "=" x 62, "Device: $device   [$ts]", "=" x 62);

    my $exp = Expect->new;
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=$timeout $user\@$device")) {
        out("ERROR: spawn failed for $device: $!");
        next;
    }

    my $ok = 0;
    $exp->expect($timeout,
        [ qr/[Pp]assword:/,          sub { $exp->send("$pass\n"); exp_continue } ],
        [ qr/yes\/no\)/i,            sub { $exp->send("yes\n");   exp_continue } ],
        [ qr/[>#]\s*$/,              sub { $ok = 1 } ],
        [ qr/[Pp]ermission denied/,  sub { out("ERROR: auth failed for $device") } ],
        [ 'timeout', sub { out("ERROR: connect timeout for $device") } ],
        [ 'eof',     sub { out("ERROR: EOF on connect to $device") } ],
    );

    unless ($ok) { $exp->soft_close; next; }

    $exp->send("terminal length 0\n");
    $exp->expect($timeout, qr/[>#]\s*$/);

    for my $cmd (
        'show bgp dampening parameters',
        'show bgp dampening suppressed-routes',
        'show bgp dampening flap-statistics',
    ) {
        $exp->send("$cmd\n");
        $exp->expect($timeout, qr/[>#]\s*$/);
        my $output = $exp->before() // '';
        $output =~ s/\r//g;
        out("", "--- $cmd ---");
        if ($output =~ /^\s*$/ || $output =~ /not configured|Invalid input|% BGP/i) {
            out("  (no output or feature not configured)");
        } else {
            for my $line (split /\n/, $output) {
                next if $line =~ /^\s*$cmd/ || $line =~ /^\s*$/;
                out("  $line");
            }
        }
    }

    $exp->send("exit\n");
    $exp->soft_close;
}

close $log_fh if $log_fh;
exit 0;

sub out {
    for my $line (@_) {
        print "$line\n";
        print $log_fh "$line\n" if $log_fh;
    }
}

sub usage {
    print <<'END';
Usage: bgp_route_dampening.pl -h <host> | -f <file> [options]

  -h, --host     Device IP or hostname
  -f, --file     File with one device per line (# lines ignored)
  -u, --user     SSH username  (env: NET_USER, default: admin)
  -p, --pass     SSH password  (env: NET_PASS)
  -l, --log      Append all output to this file
  -t, --timeout  SSH timeout seconds (default: 30)
  --help         This message

END
    exit 1;
}