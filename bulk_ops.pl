#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# Script:  003_bulk_config_push.pl
# Purpose: Push a set of configuration commands to multiple network devices
#          in bulk. Reads device list from a file (or accepts a single host
#          via CLI), applies commands from a commands file, and logs per-device
#          results.  Useful for mass configuration changes: ACL updates, NTP
#          server rollouts, SNMP community changes, banner pushes, etc.
#
# Usage:
#   Single device:
#     perl 003_bulk_config_push.pl --host 192.168.1.1 --cmds commands.txt \
#                                  --user admin --pass secret
#   Device list:
#     perl 003_bulk_config_push.pl --devlist devices.txt --cmds commands.txt \
#                                  --user admin --pass secret [--log results.log]
#
# Device list file format (one entry per line, lines starting with # ignored):
#   192.168.1.1
#   192.168.1.2
#   router-core-01.example.com
#
# Commands file format (one IOS/NX-OS command per line):
#   ntp server 10.0.0.1
#   ntp server 10.0.0.2
#   no ntp server 192.168.99.1
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH key-based auth recommended; password auth supported via --pass
#   Devices must have SSH enabled and the user must have privilege 15 or
#   sufficient rights to enter config mode.
#
# Exit codes: 0 = all devices succeeded, 1 = one or more devices failed
# =============================================================================

my ($opt_host, $opt_devlist, $opt_cmds, $opt_user, $opt_pass, $opt_log,
    $opt_timeout, $opt_dryrun);

GetOptions(
    'host=s'    => \$opt_host,
    'devlist=s' => \$opt_devlist,
    'cmds=s'    => \$opt_cmds,
    'user=s'    => \$opt_user,
    'pass=s'    => \$opt_pass,
    'log=s'     => \$opt_log,
    'timeout=i' => \$opt_timeout,
    'dry-run'   => \$opt_dryrun,
) or die "Error parsing arguments. See script header for usage.\n";

$opt_timeout //= 30;

die "ERROR: --cmds <commands_file> is required.\n"        unless $opt_cmds;
die "ERROR: --host or --devlist is required.\n"           unless $opt_host || $opt_devlist;
die "ERROR: --user is required.\n"                        unless $opt_user;
die "ERROR: --pass is required (or set \$NET_PASS env).\n" unless $opt_pass || $ENV{NET_PASS};

$opt_pass //= $ENV{NET_PASS};

# ---- Load command list -------------------------------------------------------
open(my $cfh, '<', $opt_cmds) or die "Cannot open commands file '$opt_cmds': $!\n";
my @commands = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$cfh>;
close $cfh;
die "ERROR: No commands found in '$opt_cmds'.\n" unless @commands;

# ---- Load device list --------------------------------------------------------
my @devices;
if ($opt_host) {
    push @devices, $opt_host;
}
if ($opt_devlist) {
    open(my $dfh, '<', $opt_devlist) or die "Cannot open device list '$opt_devlist': $!\n";
    push @devices, grep { /\S/ && !/^\s*#/ } map { chomp; s/\s+//gr } <$dfh>;
    close $dfh;
}
die "ERROR: No devices to process.\n" unless @devices;

# ---- Open log file -----------------------------------------------------------
my $logfh;
if ($opt_log) {
    open($logfh, '>>', $opt_log) or die "Cannot open log file '$opt_log': $!\n";
    $logfh->autoflush(1);
}

my $ts      = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $banner  = "=== Bulk Config Push  started=$ts  devices=" . scalar(@devices)
            . "  cmds=" . scalar(@commands) . " ===";
log_line($banner);

if ($opt_dryrun) {
    log_line("DRY-RUN mode — commands will be printed but NOT sent to devices.");
    log_line("Commands to apply:");
    log_line("  $_") for @commands;
}

# ---- Process each device -----------------------------------------------------
my ($ok_count, $fail_count) = (0, 0);

for my $host (@devices) {
    log_line("\n--- $host ---");

    if ($opt_dryrun) {
        log_line("[$host] SKIP (dry-run)");
        $ok_count++;
        next;
    }

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $host,
            user        => $opt_user,
            password    => $opt_pass,
            raw_pty     => 1,
            timeout     => $opt_timeout,
            ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
    };
    if ($@ || !$ssh) {
        log_line("[$host] ERROR: Could not create SSH object: $@");
        $fail_count++;
        next;
    }

    my $login_output = eval { $ssh->login() };
    if ($@ || !defined $login_output) {
        log_line("[$host] ERROR: Login failed: $@");
        $fail_count++;
        next;
    }

    # Disable paging so output is not truncated
    $ssh->exec('terminal length 0');

    # Enter privileged exec mode if not already there
    if ($login_output !~ /\#\s*$/) {
        $ssh->send('enable');
        my $en = $ssh->waitfor('Password:|#', $opt_timeout);
        if ($en =~ /Password:/) {
            $ssh->send($opt_pass);
            $ssh->waitfor('#', $opt_timeout);
        }
    }

    # Enter global config mode
    my $cfg_out = $ssh->exec('configure terminal');
    if ($cfg_out !~ /config/i) {
        log_line("[$host] ERROR: Could not enter config mode. Output: $cfg_out");
        $fail_count++;
        eval { $ssh->close() };
        next;
    }

    # Push commands
    my $had_error = 0;
    for my $cmd (@commands) {
        my $out = $ssh->exec($cmd);
        log_line("[$host] CMD: $cmd");
        if ($out =~ /Invalid|Incomplete|Error|% /i) {
            log_line("[$host] WARN: $out");
            $had_error = 1;
        }
    }

    # Exit config mode and save
    $ssh->exec('end');
    my $wr = $ssh->exec('write memory');
    if ($wr =~ /\[OK\]|Copy complete/i) {
        log_line("[$host] Config saved successfully.");
    } else {
        log_line("[$host] WARN: 'write memory' response unclear: $wr");
    }

    eval { $ssh->close() };

    if ($had_error) {
        log_line("[$host] COMPLETED WITH WARNINGS");
        $fail_count++;
    } else {
        log_line("[$host] SUCCESS");
        $ok_count++;
    }
}

# ---- Summary -----------------------------------------------------------------
my $end_ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
log_line("\n=== Summary  ended=$end_ts  success=$ok_count  failed=$fail_count ===");
close $logfh if $logfh;

exit($fail_count > 0 ? 1 : 0);

# ---- Helpers -----------------------------------------------------------------
sub log_line {
    my ($msg) = @_;
    print "$msg\n";
    print $logfh "$msg\n" if $logfh;
}