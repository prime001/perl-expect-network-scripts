#!/usr/bin/perl
# =============================================================================
# interface_errors.pl - Interface Error Counter Audit via SSH/Expect
# =============================================================================
# Purpose:
#   SSH into Cisco IOS/IOS-XE devices and audit interface error counters
#   (CRC, input errors, output drops, runts). Flags interfaces above
#   configurable thresholds to identify bad cables, duplex mismatches,
#   and oversubscribed uplinks before they cause outages.
#
# Usage:
#   ./interface_errors.pl -h 192.168.1.1 [-u admin] [-p secret] [-l out.log]
#   ./interface_errors.pl -f devices.txt [-u admin] [-l out.log]
#
# Prerequisites:
#   cpan install Expect
#   Set DEVICE_USER / DEVICE_PASS env vars or use -u/-p flags.
#   SSH key auth works; omit -p and the password expect branch is skipped.
#
# Thresholds:
#   Override via env: ERR_THRESHOLD (default 100), DROP_THRESHOLD (default 50)
# =============================================================================

use strict;
use warnings;
use Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my $err_threshold  = $ENV{ERR_THRESHOLD}  // 100;
my $drop_threshold = $ENV{DROP_THRESHOLD} // 50;
my $ssh_timeout    = 15;

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log);
GetOptions(
    'h|host=s' => \$opt_host,
    'f|file=s' => \$opt_file,
    'u|user=s' => \$opt_user,
    'p|pass=s' => \$opt_pass,
    'l|log=s'  => \$opt_log,
) or die "Usage: $0 -h HOST|-f FILE [-u user] [-p pass] [-l logfile]\n";

die "Specify -h <host> or -f <file>\n" unless $opt_host || $opt_file;

my $user = $opt_user // $ENV{DEVICE_USER} // 'admin';
my $pass = $opt_pass // $ENV{DEVICE_PASS} // '';

my @devices;
if ($opt_host) {
    @devices = ($opt_host);
} else {
    open(my $fh, '<', $opt_file) or die "Cannot open device list '$opt_file': $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
    die "No devices found in $opt_file\n" unless @devices;
}

my $log_fh;
if ($opt_log) {
    open($log_fh, '>>', $opt_log) or die "Cannot open log '$opt_log': $!\n";
}

my $run_ts = strftime('%Y-%m-%d %H:%M:%S', localtime);

sub emit {
    my ($msg) = @_;
    print STDOUT $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my ($host) = @_;
    emit("\n=== $host  [$run_ts] ===\n");

    my $exp = Expect->new;
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    $exp->spawn('ssh',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'ConnectTimeout=10',
        '-o', 'BatchMode=no',
        "$user\@$host"
    ) or do { emit("ERROR: Cannot spawn SSH to $host: $!\n"); return; };

    my $authed = $exp->expect($ssh_timeout,
        [ qr/[Pp]assword[: ]+$/,
          sub { $exp->send("$pass\n"); exp_continue; } ],
        [ qr/yes\/no/,
          sub { $exp->send("yes\n"); exp_continue; } ],
        [ qr/[>#]\s*$/,      sub { 1 } ],
        [ 'timeout',         sub { emit("ERROR: Login timeout on $host\n"); } ],
        [ 'eof',             sub { emit("ERROR: SSH connection failed on $host\n"); } ],
    );
    return unless $authed;

    $exp->send("terminal length 0\n");
    $exp->expect($ssh_timeout, qr/[>#]\s*$/);

    $exp->send("show interfaces\n");
    my $raw = '';
    $exp->expect(30,
        [ qr/[>#]\s*$/, sub { $raw = $exp->before(); } ],
        [ 'timeout',    sub { emit("ERROR: Command timed out on $host\n"); } ],
    );

    $exp->send("exit\n");
    $exp->soft_close();

    return unless $raw;
    parse_counters($host, $raw);
}

sub parse_counters {
    my ($host, $text) = @_;
    my (%flagged, $iface);

    for my $line (split /\n/, $text) {
        if ($line =~ /^(\S+)\s+is\s+(?:up|down|administratively down)/i) {
            $iface = $1;
        }
        next unless $iface;

        if ($line =~ /(\d+)\s+input errors/)  { $flagged{$iface}{input_errors} = $1  if $1 >= $err_threshold; }
        if ($line =~ /(\d+)\s+CRC/)           { $flagged{$iface}{CRC}          = $1  if $1 >= $err_threshold; }
        if ($line =~ /(\d+)\s+output drops/)  { $flagged{$iface}{output_drops} = $1  if $1 >= $drop_threshold; }
        if ($line =~ /(\d+)\s+runts/)         { $flagged{$iface}{runts}        = $1  if $1 > 0; }
        if ($line =~ /(\d+)\s+giants/)        { $flagged{$iface}{giants}       = $1  if $1 > 0; }

        # Remove entry if no counters actually flagged for this interface
        delete $flagged{$iface} if exists $flagged{$iface} && !%{$flagged{$iface}};
    }

    if (%flagged) {
        emit("FLAGGED (threshold: errors>=$err_threshold, drops>=$drop_threshold):\n");
        for my $if_name (sort keys %flagged) {
            my @parts = map { "$_=$flagged{$if_name}{$_}" } sort keys %{$flagged{$if_name}};
            emit(sprintf "  %-35s %s\n", $if_name, join('  ', @parts));
        }
    } else {
        emit("OK - all interfaces within error thresholds\n");
    }
}

audit_device($_) for @devices;
emit("\nAudit complete. " . scalar(@devices) . " device(s) checked.\n");
close $log_fh if $log_fh;