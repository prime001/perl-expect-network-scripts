#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# bulk_config_push.pl - Bulk Configuration Deployment Tool
# =============================================================================
# Purpose:
#   Pushes a configuration snippet (ACL, route-map, prefix-list, etc.) to
#   multiple network devices in sequence. Captures pre/post diffs and logs
#   success or failure per device. Designed for controlled maintenance windows.
#
# Usage:
#   perl bulk_config_push.pl --devices devices.txt --config config.txt [OPTIONS]
#   perl bulk_config_push.pl --host 192.168.1.1 --config config.txt [OPTIONS]
#
# Options:
#   --devices FILE    File with one device IP/hostname per line
#   --host HOST       Single device IP or hostname
#   --config FILE     File containing IOS config lines to push
#   --user USER       SSH username (default: $USER env var)
#   --pass PASS       SSH password (prompted if omitted)
#   --verify CMD      Show command to run after push for verification
#   --log FILE        Log file path (default: bulk_push_TIMESTAMP.log)
#   --timeout SEC     Per-command timeout in seconds (default: 30)
#   --dry-run         Print config lines without pushing
#
# Prerequisites:
#   cpanm Net::SSH::Expect
#   SSH access to devices; enable password or privilege already configured
#
# Author: NetAutoCommitter Portfolio
# =============================================================================

my ($devices_file, $host, $config_file, $user, $pass, $verify_cmd, $log_file,
    $timeout, $dry_run);

$timeout = 30;
$user    = $ENV{USER} || 'admin';

GetOptions(
    'devices=s' => \$devices_file,
    'host=s'    => \$host,
    'config=s'  => \$config_file,
    'user=s'    => \$user,
    'pass=s'    => \$pass,
    'verify=s'  => \$verify_cmd,
    'log=s'     => \$log_file,
    'timeout=i' => \$timeout,
    'dry-run'   => \$dry_run,
) or die "Invalid options. See header for usage.\n";

die "ERROR: --config FILE is required\n" unless $config_file;
die "ERROR: --devices or --host is required\n" unless $devices_file || $host;
die "ERROR: Config file '$config_file' not found\n" unless -f $config_file;

my @config_lines = do {
    open my $fh, '<', $config_file or die "Cannot open config: $!\n";
    grep { /\S/ && !/^\s*!/ } map { chomp; $_ } <$fh>;
};
die "ERROR: Config file is empty\n" unless @config_lines;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $devices_file or die "Cannot open devices file: $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { chomp; s/\s+//gr } <$fh>;
}
die "ERROR: No devices found\n" unless @devices;

unless ($pass) {
    print "SSH password for $user: ";
    system('stty', '-echo');
    chomp($pass = <STDIN>);
    system('stty', 'echo');
    print "\n";
}

my $timestamp = strftime('%Y%m%d_%H%M%S', localtime);
$log_file //= "bulk_push_${timestamp}.log";

open my $LOG, '>>', $log_file or die "Cannot open log: $!\n";

sub log_msg {
    my ($msg) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    print        "[$ts] $msg\n";
    print $LOG   "[$ts] $msg\n";
}

sub push_config {
    my ($device) = @_;

    log_msg("--- Connecting to $device ---");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    eval { $ssh->login() };
    if ($@) {
        log_msg("FAIL [$device]: Authentication/connection error: $@");
        return 0;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('>', 5);
    $ssh->send('terminal width 0');
    $ssh->waitfor('>', 5);

    if ($verify_cmd) {
        log_msg("[$device] PRE-CHECK: $verify_cmd");
        $ssh->send($verify_cmd);
        my $pre = $ssh->waitfor('>', $timeout);
        log_msg("[$device] PRE:\n$pre");
    }

    $ssh->send('configure terminal');
    my $resp = $ssh->waitfor('\(config\)', 10);
    unless ($resp =~ /\(config\)/) {
        log_msg("FAIL [$device]: Could not enter config mode");
        return 0;
    }

    for my $line (@config_lines) {
        log_msg("[$device] >> $line");
        $ssh->send($line);
        $resp = $ssh->waitfor('config', $timeout);
        if ($resp =~ /(?:Invalid|Error|Ambiguous)/i) {
            log_msg("FAIL [$device]: IOS error on '$line': $resp");
            $ssh->send('abort');
            $ssh->waitfor('>', 10);
            return 0;
        }
    }

    $ssh->send('end');
    $ssh->waitfor('>', 10);

    $ssh->send('write memory');
    $resp = $ssh->waitfor('(?:OK|\[OK\]|Copy complete)', $timeout);
    if ($resp =~ /(?:OK|\[OK\]|Copy complete)/i) {
        log_msg("OK  [$device]: Config saved");
    } else {
        log_msg("WARN [$device]: 'write memory' response unclear: $resp");
    }

    if ($verify_cmd) {
        log_msg("[$device] POST-CHECK: $verify_cmd");
        $ssh->send($verify_cmd);
        my $post = $ssh->waitfor('>', $timeout);
        log_msg("[$device] POST:\n$post");
    }

    $ssh->close();
    return 1;
}

# Main execution
my ($ok, $fail) = (0, 0);
log_msg("Starting bulk config push to " . scalar(@devices) . " device(s)");
log_msg("Config: $config_file (" . scalar(@config_lines) . " lines)");

if ($dry_run) {
    log_msg("DRY-RUN mode — config lines to be pushed:");
    log_msg("  $_") for @config_lines;
    log_msg("Devices: " . join(', ', @devices));
    exit 0;
}

for my $dev (@devices) {
    if (push_config($dev)) { $ok++ } else { $fail++ }
}

log_msg("=== Summary: $ok succeeded, $fail failed ===");
log_msg("Log written to: $log_file");
close $LOG;

exit($fail > 0 ? 1 : 0);