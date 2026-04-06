The existing scripts aren't in this working directory, so I'll write the NTP check script directly based on the established conventions from the script naming pattern.

```perl
#!/usr/bin/perl
# =============================================================================
# 006_ntp_check.pl - NTP Synchronization Audit for Network Devices
# =============================================================================
# Purpose:
#   Connects to one or more network devices via SSH and audits NTP status.
#   Checks sync state, stratum, reference clock, and peer associations.
#   Flags devices that are unsynchronized, at high stratum, or using
#   unexpected NTP servers.
#
# Usage:
#   Single device:   ./006_ntp_check.pl -h 192.168.1.1
#   Device list:     ./006_ntp_check.pl -f devices.txt
#   With log file:   ./006_ntp_check.pl -f devices.txt -l ntp_audit.log
#   Custom NTP:      ./006_ntp_check.pl -f devices.txt -n 10.0.0.1,10.0.0.2
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#   SSH key auth recommended; password via env var NET_DEVICE_PASS
#
# Device file format (one per line):
#   192.168.1.1
#   192.168.1.2  username  # optional per-device username override
#
# Exit codes: 0=all synced, 1=issues found, 2=script error
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

# --- CLI args ----------------------------------------------------------------
my ($host, $device_file, $log_file, $username, $ntp_servers_arg);
my $max_stratum   = 5;
my $timeout       = 15;

GetOptions(
    'h|host=s'       => \$host,
    'f|file=s'       => \$device_file,
    'l|log=s'        => \$log_file,
    'u|user=s'       => \$username,
    'n|ntp=s'        => \$ntp_servers_arg,
    's|stratum=i'    => \$max_stratum,
    't|timeout=i'    => \$timeout,
) or die "Usage: $0 [-h host | -f file] [-l logfile] [-u user] [-n ntp1,ntp2] [-s max_stratum]\n";

die "Specify -h <host> or -f <file>\n" unless $host || $device_file;

$username //= $ENV{NET_DEVICE_USER} // 'admin';
my $password      = $ENV{NET_DEVICE_PASS} // '';
my @approved_ntps = $ntp_servers_arg ? split(/,/, $ntp_servers_arg) : ();

# --- Logging setup -----------------------------------------------------------
my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
    $log_fh->autoflush(1);
}

sub log_out {
    my ($line) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    print "[$ts] $line\n";
    print $log_fh "[$ts] $line\n" if $log_fh;
}

# --- Build device list -------------------------------------------------------
my @devices;
if ($host) {
    push @devices, { ip => $host, user => $username };
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        next unless length;
        my ($ip, $u) = split(/\s+/, $_, 2);
        push @devices, { ip => $ip, user => $u // $username };
    }
    close $fh;
}

# --- Per-device check --------------------------------------------------------
my $issues = 0;

for my $dev (@devices) {
    my $ip   = $dev->{ip};
    my $user = $dev->{user};

    log_out("=== Checking $ip (user: $user) ===");

    my $ssh = Net::SSH::Expect->new(
        host        => $ip,
        user        => $user,
        password    => $password,
        timeout     => $timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !$login_output) {
        log_out("  [FAIL] SSH connection/auth failed for $ip: $@");
        $issues++;
        next;
    }

    # Cisco IOS / IOS-XE: show ntp status + associations
    $ssh->send('terminal length 0');
    $ssh->waitfor('\$|#|>', 5);

    $ssh->send('show ntp status');
    my $ntp_status = $ssh->waitfor('\$|#|>', $timeout) // '';

    $ssh->send('show ntp associations');
    my $ntp_assoc = $ssh->waitfor('\$|#|>', $timeout) // '';

    $ssh->send('exit');

    # Parse sync state
    if ($ntp_status =~ /Clock is (\S+)/i) {
        my $state = $1;
        if ($state =~ /synchronized/i) {
            log_out("  [OK]   Sync state  : $state");
        } else {
            log_out("  [WARN] Sync state  : $state (NOT synchronized)");
            $issues++;
        }
    } else {
        log_out("  [WARN] Could not parse NTP sync state");
        $issues++;
    }

    if ($ntp_status =~ /stratum\s+(\d+)/i) {
        my $stratum = $1;
        my $tag = ($stratum <= $max_stratum) ? '[OK]  ' : '[WARN]';
        log_out("  $tag Stratum     : $stratum (max allowed: $max_stratum)");
        $issues++ if $stratum > $max_stratum;
    }

    if ($ntp_status =~ /reference is\s+(\S+)/i) {
        my $ref = $1;
        if (@approved_ntps && !grep { $ref =~ /\Q$_\E/ } @approved_ntps) {
            log_out("  [WARN] Reference   : $ref (not in approved list)");
            $issues++;
        } else {
            log_out("  [OK]   Reference   : $ref");
        }
    }

    # Count reachable peers
    my $reachable = () = $ntp_assoc =~ /\*|#|\+/g;
    log_out("  [INFO] NTP peers   : $reachable reachable");
    if ($reachable == 0) {
        log_out("  [WARN] No reachable NTP peers");
        $issues++;
    }
}

log_out("=== Audit complete. Issues found: $issues ===");
close $log_fh if $log_fh;
exit($issues ? 1 : 0);
```