#!/usr/bin/perl
# =============================================================================
# stp_audit.pl - Spanning Tree Protocol Status Audit via SSH
#
# Purpose:
#   Audits STP state across Cisco IOS/IOS-XE switches: identifies root bridge
#   role, blocking ports, topology change counts, PortFast/BPDU Guard status,
#   and flags instability indicators useful for troubleshooting or compliance.
#
# Usage:
#   ./stp_audit.pl <host> <username> <password>
#   ./stp_audit.pl --file hosts.txt admin secretpass [--log stp.log]
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access with enable-level privilege (or provide enable pass via ENV)
#
# Environment:
#   NET_USER   - SSH username (overridden by positional arg)
#   NET_PASS   - SSH/enable password
#   NET_ENABLE - Separate enable password (optional; falls back to NET_PASS)
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config pass_through);
use POSIX qw(strftime);

my ($log_file, $host_file);
GetOptions(
    'log|l=s'  => \$log_file,
    'file|f=s' => \$host_file,
) or die "Usage: $0 [--log file] [--file hosts.txt] [host] [user] [pass]\n";

my ($host_arg, $user, $pass) = @ARGV;
$user   //= $ENV{NET_USER} // 'admin';
$pass   //= $ENV{NET_PASS}  or die "Password required (3rd arg or NET_PASS env)\n";
my $enable_pass = $ENV{NET_ENABLE} // $pass;

my @hosts;
if ($host_file) {
    open my $fh, '<', $host_file or die "Cannot open $host_file: $!\n";
    @hosts = grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
    close $fh;
} elsif ($host_arg) {
    @hosts = ($host_arg);
} else {
    die "Provide a host argument or --file hosts.txt\n";
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
    emit("\n[$ts] === STP Audit: $host ===\n");

    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        user       => $user,
        password   => $pass,
        raw_pty    => 1,
        timeout    => 15,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=no',
    );

    eval {
        $ssh->run_ssh() or die "SSH failed to start\n";
        my $login = $ssh->waitfor('(?i:password|#|>)', 12)
            or die "No login prompt received\n";

        if ($ssh->match() =~ /[Pp]assword/) {
            $ssh->send($pass);
            $ssh->waitfor('(?:#|>)', 10) or die "Authentication failed\n";
        }

        if ($ssh->match() =~ />$/) {
            $ssh->send('enable');
            $ssh->waitfor('[Pp]assword:', 5) or die "Enable prompt not received\n";
            $ssh->send($enable_pass);
            $ssh->waitfor('#', 10) or die "Enable authentication failed\n";
        }

        $ssh->send('terminal length 0');
        $ssh->waitfor('#', 5);

        $ssh->send('show spanning-tree summary');
        my $summary = $ssh->waitfor('#', 15) // '';

        $ssh->send('show spanning-tree detail');
        my $detail = $ssh->waitfor('#', 20) // '';

        $ssh->send('exit');
        $ssh->close();

        parse_and_report($host, $summary, $detail);
    };

    if ($@) {
        (my $err = $@) =~ s/\n+$//;
        emit("  ERROR connecting to $host: $err\n");
    }
}

sub parse_and_report {
    my ($host, $summary, $detail) = @_;

    my $is_root = ($summary =~ /^This bridge is the root/im) ? 'YES' : 'NO';
    emit("  Root bridge role:         $is_root\n");

    my @vlans = ($summary =~ /^(VLAN\d+)\b/gim);
    emit("  Active STP instances:     " . scalar(@vlans) . "\n");

    my @blocking = ($detail =~ /(\S+(?:Eth|Gi|Fa|Te)\S*)\s+of\s+\S+\s+is\s+(?:BLK|Blocking)/gi);
    emit("  Blocking ports:           " . (@blocking ? join(', ', @blocking) : 'none') . "\n");

    my $total_tc = 0;
    $total_tc += $_ for ($detail =~ /Number of topology changes\s+(\d+)/gi);
    emit("  Total topology changes:   $total_tc\n");

    my ($last_tc) = ($detail =~ /last change occurred\s+(\d+\s+\w+\s+ago)/i);
    if ($last_tc) {
        emit("  Last topology change:     $last_tc\n");
        if ($last_tc =~ /^\d+\s+second/i) {
            emit("  *** WARNING: topology change within last 60s - possible instability\n");
        }
    }

    my $portfast_count = () = ($detail =~ /Portfast\s+enabled/gi);
    emit("  PortFast-enabled ports:   $portfast_count\n");

    my ($bpduguard) = ($summary =~ /BPDU\s+Guard\s+(\S+)/i);
    emit("  BPDU Guard (global):      " . ($bpduguard // 'not detected') . "\n");

    my @disputed = ($detail =~ /(\S+)\s+.*?Disputed/gi);
    if (@disputed) {
        emit("  *** WARNING: Disputed BPDU on: " . join(', ', @disputed) . "\n");
    }
}

emit("STP Audit started: " . strftime('%Y-%m-%d %H:%M:%S', localtime) . "\n");
emit("Targets: " . scalar(@hosts) . " device(s)\n");

audit_device($_) for @hosts;

emit("\nAudit complete: " . strftime('%Y-%m-%d %H:%M:%S', localtime) . "\n");
close $log_fh if $log_fh;