The output should be just the script — here it is:

#!/usr/bin/perl
# =============================================================================
# qos_audit.pl - QoS Policy Audit for Cisco IOS/IOS-XE Devices
# =============================================================================
# Purpose:
#   Audits Quality of Service configurations across network devices via SSH.
#   Collects applied service-policies per interface, policy-map/class-map
#   definitions, and DSCP/CoS marking criteria. Useful for validating QoS
#   consistency before and after network changes or during compliance checks.
#
# Usage:
#   Single device:  perl qos_audit.pl -h 192.168.1.1
#   Device list:    perl qos_audit.pl -f devices.txt
#   With logging:   perl qos_audit.pl -f devices.txt -l /tmp/qos_$(date +%F).log
#   Override creds: perl qos_audit.pl -f devices.txt -u netops -p s3cr3t -e en4ble
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#   SSH reachability; read-only ('show') privilege sufficient
#   devices.txt: one IP or hostname per line; lines starting with # are skipped
#
# Environment:
#   NET_USER, NET_PASS, NET_ENABLE  — credential defaults (avoids CLI exposure)
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my $username    = $ENV{NET_USER}   // 'admin';
my $password    = $ENV{NET_PASS}   // '';
my $enable_pw   = $ENV{NET_ENABLE} // '';
my $timeout     = 25;
my ($opt_host, $opt_file, $opt_log, $opt_user, $opt_pass, $opt_enable, $opt_help);

GetOptions(
    'h|host=s'   => \$opt_host,
    'f|file=s'   => \$opt_file,
    'l|log=s'    => \$opt_log,
    'u|user=s'   => \$opt_user,
    'p|pass=s'   => \$opt_pass,
    'e|enable=s' => \$opt_enable,
    'help'       => \$opt_help,
) or die "Argument error. Run with --help for usage.\n";

if ($opt_help || (!$opt_host && !$opt_file)) {
    print "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-e enable] [-l logfile]\n";
    exit 0;
}

$username  = $opt_user   if $opt_user;
$password  = $opt_pass   if $opt_pass;
$enable_pw = $opt_enable if $opt_enable;

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open my $fh, '<', $opt_file or die "Cannot open $opt_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*$/ || /^\s*#/; push @devices, $_; }
    close $fh;
}

my $LOG;
if ($opt_log) {
    open $LOG, '>>', $opt_log or die "Cannot open log $opt_log: $!\n";
}

my $stamp = strftime('%Y-%m-%d %H:%M:%S', localtime);

sub emit {
    my ($msg) = @_;
    print $msg;
    print $LOG $msg if $LOG;
}

sub audit_device {
    my ($dev) = @_;
    emit("\n" . "=" x 62 . "\n");
    emit("HOST: $dev    STARTED: $stamp\n");
    emit("=" x 62 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host       => $dev,
        user       => $username,
        password   => $password,
        raw_pty    => 1,
        timeout    => $timeout,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=8 -o BatchMode=no',
    );

    eval {
        my $banner = $ssh->login();
        die "Auth failed or unexpected prompt\n" unless $banner =~ /[>#]/;
    };
    if ($@) {
        chomp(my $err = $@);
        emit("  [ERROR] $err\n");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('[>#]', 5);

    if ($enable_pw) {
        $ssh->send("enable");
        my $r = $ssh->waitfor('assword:|[>#]', 5);
        if ($r && $r =~ /assword:/) {
            $ssh->send($enable_pw);
            $ssh->waitfor('[>#]', 5);
        }
    }

    # --- Policy-maps defined ---
    emit("\n  [Defined Policy Maps]\n");
    $ssh->send("show policy-map");
    my $pm_out = $ssh->waitfor('[>#]', 20) // '';
    my @pmaps = ($pm_out =~ /^\s*Policy Map\s+(\S+)/mg);
    emit(@pmaps ? "  " . join(', ', @pmaps) . "\n" : "  None configured\n");

    # --- Interface service-policy bindings ---
    emit("\n  [Interface Service-Policy Bindings]\n");
    $ssh->send("show policy-map interface");
    my $ipm_out = $ssh->waitfor('[>#]', 25) // '';

    my $cur_iface = '';
    my $binding_count = 0;
    for my $line (split /\n/, $ipm_out) {
        if ($line =~ /^\s{0,2}(\S+(?:Ethernet|Serial|Tunnel|Port|Vlan)\S*)/i) {
            $cur_iface = $1;
        } elsif ($line =~ /Service-policy\s+(input|output):\s+(\S+)/i) {
            emit(sprintf("  %-35s %s: %s\n", $cur_iface, $1, $2));
            $binding_count++;
        }
    }
    emit("  No service policies applied to interfaces\n") unless $binding_count;

    # --- DSCP/CoS/precedence match criteria ---
    emit("\n  [QoS Match Criteria (DSCP / CoS / Precedence)]\n");
    $ssh->send("show class-map");
    my $cm_out = $ssh->waitfor('[>#]', 15) // '';
    my @matches = grep { /match.*(?:dscp|cos|precedence|protocol)/i } split /\n/, $cm_out;
    if (@matches) {
        for my $m (@matches) {
            $m =~ s/^\s+//;
            emit("  $m\n") if length($m) > 3;
        }
    } else {
        emit("  No DSCP/CoS/precedence match entries found\n");
    }

    $ssh->close();
    emit("\n  [OK] Audit complete for $dev\n");
}

emit("QoS Audit Report — $stamp\n");
audit_device($_) for @devices;
emit("\n--- Finished. Devices processed: " . scalar(@devices) . " ---\n");
close $LOG if $LOG;