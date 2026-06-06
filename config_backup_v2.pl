#!/usr/bin/perl
#
# config_diff.pl -- Detect unsaved configuration changes on Cisco IOS/IOS-XE devices
#
# Connects via SSH using Expect, retrieves both running-config and startup-config,
# then compares them locally to surface lines that exist in one but not the other.
# Non-zero exit when diffs are found -- suitable for cron jobs or monitoring hooks
# that alert when engineers make changes but forget "copy run start" / "write mem".
#
# Usage:
#   config_diff.pl -h <host> [-h <host> ...] -u <user> -p <pass> [-l <log>]
#   config_diff.pl -f <hostfile>              -u <user> -p <pass> [-l <log>]
#
# Options:
#   -h, --host      Device hostname or IP (repeatable for multiple devices)
#   -f, --file      Plain-text file with one hostname/IP per line (# = comment)
#   -u, --user      SSH username
#   -p, --password  SSH password
#   -l, --logfile   Append results to this file in addition to STDOUT
#   -t, --timeout   Per-command timeout in seconds (default: 45)
#
# Prerequisites:
#   perl -MCPAN -e 'install Expect'
#   SSH access to device with credentials that can read both config stores
#
# Exit codes:
#   0 = all devices clean (running matches startup)
#   1 = at least one device has unsaved changes
#   2 = connection or authentication failure on at least one device
#

use strict;
use warnings;
use Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX        qw(strftime);

my (@hosts, $user, $pass, $logfile, $hostfile, $timeout);

GetOptions(
    'host|h=s'     => \@hosts,
    'file|f=s'     => \$hostfile,
    'user|u=s'     => \$user,
    'password|p=s' => \$pass,
    'logfile|l=s'  => \$logfile,
    'timeout|t=i'  => \$timeout,
) or usage();

$timeout //= 45;
usage() unless $user && $pass && (@hosts || $hostfile);

if ($hostfile) {
    open my $fh, '<', $hostfile or die "Cannot open $hostfile: $!\n";
    while (<$fh>) { chomp; push @hosts, $_ if /\S/ && !/^\s*#/; }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!\n";
}

out("# config_diff  started=" . strftime('%Y-%m-%d %H:%M:%S', localtime));

my $exit_code = 0;
for my $host (@hosts) {
    my $rc = check_device($host);
    $exit_code = $rc if $rc > $exit_code;
}

out("# config_diff  finished=" . strftime('%Y-%m-%d %H:%M:%S', localtime)
    . "  exit=$exit_code");
close $log_fh if $log_fh;
exit $exit_code;

# ---------------------------------------------------------------------------

sub check_device {
    my ($host) = @_;
    out("\n[$host] Connecting as $user ...");

    my $exp = Expect->new;
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn('ssh', '-o', 'StrictHostKeyChecking=no',
                                '-o', 'ConnectTimeout=10',
                                "${user}\@${host}")) {
        out("[$host] ERROR: could not spawn SSH process");
        return 2;
    }

    my $authed = 0;
    $exp->expect($timeout,
        [ qr/(?:yes\/no)/i,       sub { $_[0]->send("yes\n");   exp_continue } ],
        [ qr/[Pp]assword:/,       sub { $_[0]->send("$pass\n"); exp_continue } ],
        [ qr/[>#]/,               sub { $authed = 1 } ],
        [ qr/denied|Permission/i, sub { } ],
        [ 'timeout',              sub { } ],
    );

    unless ($authed) {
        out("[$host] ERROR: authentication failed or connection timed out");
        $exp->hard_close;
        return 2;
    }

    send_cmd($exp, "terminal length 0\n");

    my $running = send_cmd($exp, "show running-config\n");
    my $startup  = send_cmd($exp, "show startup-config\n");

    $exp->send("exit\n");
    $exp->soft_close;

    # Strip comment/cosmetic lines that vary by timestamp and add false-positive noise
    my @run   = grep { /\S/ && !/^\s*!/ && !/^(?:Building|Current|Last)\s/ }
                split(/\r?\n/, $running);
    my @start = grep { /\S/ && !/^\s*!/ && !/^(?:Building|Current|Last)\s/ }
                split(/\r?\n/, $startup);

    my %in_startup = map { $_ => 1 } @start;
    my %in_running  = map { $_ => 1 } @run;

    my @added   = grep { !$in_startup{$_} } @run;    # in running, not startup
    my @removed = grep { !$in_running{$_}  } @start;  # in startup, not running

    if (!@added && !@removed) {
        out("[$host] OK  running-config matches startup-config");
        return 0;
    }

    out("[$host] DIFF  unsaved changes detected (write mem needed)");
    if (@added) {
        out("[$host]   +present in running, missing from startup ("
            . scalar(@added) . " lines):");
        out("[$host]     + $_") for @added;
    }
    if (@removed) {
        out("[$host]   -present in startup, missing from running ("
            . scalar(@removed) . " lines):");
        out("[$host]     - $_") for @removed;
    }
    return 1;
}

sub send_cmd {
    my ($exp, $cmd) = @_;
    $exp->send($cmd);
    $exp->expect($timeout, [ qr/[>#]/ ]);
    return $exp->before // '';
}

sub out {
    my ($msg) = @_;
    print "$msg\n";
    print {$log_fh} "$msg\n" if $log_fh;
}

sub usage {
    (my $name = $0) =~ s{.*/}{};
    print "Usage:\n";
    print "  $name -h <host> [-h <host>...] -u <user> -p <pass> [-l <log>] [-t <sec>]\n";
    print "  $name -f <hostfile>             -u <user> -p <pass> [-l <log>] [-t <sec>]\n";
    exit 2;
}