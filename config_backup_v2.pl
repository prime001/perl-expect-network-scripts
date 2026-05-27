#!/usr/bin/perl
#
# config_compliance.pl - Network Device Configuration Compliance Auditor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and audits the running
#   configuration against a baseline compliance ruleset. Reports which
#   required settings are missing and which prohibited settings are present.
#   Useful for pre-audit checks, change-window gates, and periodic hardening
#   verification across a fleet.
#
# Usage:
#   Single device:  ./config_compliance.pl -h 192.168.1.1
#   Device list:    ./config_compliance.pl -f devices.txt
#   With logging:   ./config_compliance.pl -h 192.168.1.1 -l compliance.log
#   Custom creds:   ./config_compliance.pl -h 192.168.1.1 -u netops -p secret
#
# Prerequisites:
#   cpan install Net::SSH::Expect Getopt::Long
#   SSH access to target devices (key-based preferred)
#   Set NET_USER / NET_PASS env vars or use -u / -p flags
#
# Exit codes: 0 = all devices compliant, 1 = one or more failures
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($host_arg, $file_arg, $log_file, $username, $password, $enable_pass);
$username    = $ENV{NET_USER}   // 'admin';
$password    = $ENV{NET_PASS}   // '';
$enable_pass = $ENV{NET_ENABLE} // $password;

GetOptions(
    'h|host=s'   => \$host_arg,
    'f|file=s'   => \$file_arg,
    'l|log=s'    => \$log_file,
    'u|user=s'   => \$username,
    'p|pass=s'   => \$password,
    'e|enable=s' => \$enable_pass,
) or die "Usage: $0 -h <host>|-f <file> [-l logfile] [-u user] [-p pass] [-e enable]\n";

die "Specify -h <host> or -f <file>\n" unless $host_arg || $file_arg;

# Patterns that MUST be present in running-config
my %REQUIRED = (
    'aaa_new_model'               => qr/aaa new-model/,
    'banner_motd'                 => qr/banner (motd|login)/,
    'exec_timeout_configured'     => qr/exec-timeout [1-9]/,
    'logging_buffered'            => qr/logging buffered/,
    'ntp_server_configured'       => qr/ntp server\s+\S/,
    'service_password_encryption' => qr/service password-encryption/,
    'ssh_version_2'               => qr/ip ssh version 2/,
    'vty_transport_ssh_only'      => qr/transport input ssh/,
);

# Patterns that MUST NOT be present in running-config
my %PROHIBITED = (
    'enable_password_cleartext'  => qr/^enable password\s+\S/m,
    'ip_http_server_enabled'     => qr/^ip http server$/m,
    'snmp_community_public'      => qr/snmp-server community public\b/i,
    'snmp_community_private'     => qr/snmp-server community private\b/i,
    'telnet_transport_on_vty'    => qr/transport input telnet$/m,
    'no_service_tcp_small_svcs'  => qr/^service tcp-small-servers/m,
);

my @hosts;
if ($host_arg) {
    @hosts = ($host_arg);
} else {
    open my $fh, '<', $file_arg or die "Cannot open $file_arg: $!\n";
    @hosts = grep { /\S/ && !/^\s*#/ } <$fh>;
    chomp @hosts;
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
    $log_fh->autoflush(1);
}

sub emit {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my ($host) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    emit("\n[$ts] Auditing: $host\n" . ('=' x 58) . "\n");

    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        user       => $username,
        password   => $password,
        raw_pty    => 1,
        timeout    => 20,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=no',
    );

    eval { $ssh->login() };
    if ($@) {
        emit("  [ERROR] SSH login failed: $@\n");
        return 1;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('[\$#>]', 5);

    # Enter privileged mode if at user exec level
    $ssh->send("enable\n");
    my $resp = $ssh->waitfor('(?:assword|#)', 8);
    if (defined $resp && $resp =~ /assword/) {
        $ssh->send("$enable_pass\n");
        $ssh->waitfor('#', 8);
    }

    my $config = $ssh->exec("show running-config");
    $ssh->send("exit\n");
    $ssh->close();

    unless ($config && length($config) > 100) {
        emit("  [ERROR] Failed to retrieve running-config (got " . length($config // '') . " bytes)\n");
        return 1;
    }

    my ($pass, $fail) = (0, 0);

    emit("\n  REQUIRED SETTINGS:\n");
    for my $rule (sort keys %REQUIRED) {
        if ($config =~ $REQUIRED{$rule}) {
            emit(sprintf("    [PASS] %s\n", $rule));
            $pass++;
        } else {
            emit(sprintf("    [FAIL] %s  <-- MISSING\n", $rule));
            $fail++;
        }
    }

    emit("\n  PROHIBITED SETTINGS:\n");
    for my $rule (sort keys %PROHIBITED) {
        if ($config =~ $PROHIBITED{$rule}) {
            emit(sprintf("    [FAIL] %s  <-- FOUND\n", $rule));
            $fail++;
        } else {
            emit(sprintf("    [PASS] %s\n", $rule));
            $pass++;
        }
    }

    my $total  = $pass + $fail;
    my $score  = $total ? int($pass / $total * 100) : 0;
    my $status = $fail == 0 ? 'COMPLIANT' : "NON-COMPLIANT ($fail issue(s))";
    emit(sprintf("\n  Result: %d/%d passed (%d%%)  --  %s\n", $pass, $total, $score, $status));
    return $fail > 0 ? 1 : 0;
}

my $overall = 0;
for my $host (@hosts) {
    $overall |= audit_device($host);
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
emit("\n[$ts] Audit complete. Overall status: " . ($overall ? "FAILURES DETECTED" : "ALL COMPLIANT") . "\n");
close $log_fh if $log_fh;
exit $overall;