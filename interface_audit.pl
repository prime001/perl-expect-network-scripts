The existing scripts aren't in this working directory — they're in the target repo. The names make their purposes clear. Here is the interface-audit script:

#!/usr/bin/perl
# =============================================================================
# 004_interface_audit.pl - Network Interface Health Audit
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and audits interface health.
#   Reports interfaces in down state, interfaces accumulating input/output/CRC
#   errors, and half-duplex mismatches that degrade throughput. Useful for
#   routine health checks or troubleshooting calls before a maintenance window.
#
# Usage:
#   ./004_interface_audit.pl -h <host>        Single device
#   ./004_interface_audit.pl -f <hosts_file>  One IP/hostname per line
#
#   Optional flags:
#     -u <username>   Default: $NET_USER env var or 'admin'
#     -p <password>   Default: $NET_PASS env var (prefer env over -p)
#     -l <logfile>    Append full output to logfile in addition to STDOUT
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#   SSH access to device with 'show interfaces' and 'show interfaces status'
#   privilege. Key-based auth recommended; set NET_USER/NET_PASS env vars to
#   avoid credentials in shell history.
#
# Output codes in report:
#   [DOWN]    Physical or protocol state is down
#   [ERRORS]  Non-zero input errors, CRC errors, or output errors
#   [DUPLEX]  Interface operating at half-duplex (common for mismatched links)
#
# Example:
#   NET_USER=netops NET_PASS=s3cr3t ./004_interface_audit.pl -f core_switches.txt -l audit.log
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $hosts_file, $username, $password, $logfile);
$username = $ENV{NET_USER} // 'admin';
$password = $ENV{NET_PASS} // '';

GetOptions(
    'h|host=s' => \$host,
    'f|file=s' => \$hosts_file,
    'u|user=s' => \$username,
    'p|pass=s' => \$password,
    'l|log=s'  => \$logfile,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile]\n";

die "Must specify -h <host> or -f <file>\n" unless $host || $hosts_file;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $hosts_file or die "Cannot open $hosts_file: $!\n";
    while (<$fh>) {
        chomp; next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open logfile '$logfile': $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);

sub emit {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my ($device) = @_;
    emit("\n" . "=" x 62 . "\n");
    emit("INTERFACE AUDIT  host=$device  ts=$ts\n");
    emit("=" x 62 . "\n");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host       => $device,
            user       => $username,
            password   => $password,
            raw_pty    => 1,
            timeout    => 20,
            ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=no',
        );
        $ssh->login();
    };
    if ($@) {
        emit("  ERROR: connection failed to $device: $@\n");
        return;
    }

    $ssh->exec("terminal length 0");
    my $intf_out   = $ssh->exec("show interfaces");
    my $status_out = $ssh->exec("show interfaces status");
    $ssh->close();

    # --- parse show interfaces ---
    my (%iface, $cur);
    for my $line (split /\n/, $intf_out) {
        if ($line =~ /^(\S+)\s+is\s+(up|down),\s+line protocol is\s+(up|down)/i) {
            $cur = $1;
            $iface{$cur}{phy}   = $2;
            $iface{$cur}{proto} = $3;
        }
        next unless $cur;
        $iface{$cur}{desc}       = $1 if $line =~ /^\s+Description:\s+(.+)/;
        if ($line =~ /(\d+) input errors.*?(\d+) CRC/i) {
            $iface{$cur}{in_err} = $1;
            $iface{$cur}{crc}    = $2;
        }
        $iface{$cur}{out_err} = $1 if $line =~ /(\d+) output errors/i;
    }

    # --- parse show interfaces status for duplex ---
    my %duplex;
    for my $line (split /\n/, $status_out) {
        next unless $line =~ /^(Gi|Fa|Te|Hu|Tw|Et|Po)\S*/;
        my @f = split /\s+/, $line;
        next unless @f >= 5;
        $duplex{$f[0]} = { duplex => $f[-2] // '', speed => $f[-1] // '' };
    }

    # --- report ---
    my ($n_down, $n_err, $n_dup) = (0, 0, 0);
    for my $intf (sort keys %iface) {
        my $e = $iface{$intf};
        if (($e->{phy} // '') eq 'down') {
            emit(sprintf "  [DOWN]   %-36s phy=down  proto=%-4s  desc=%s\n",
                $intf, $e->{proto} // '?', $e->{desc} // '(none)');
            $n_down++;
        }
        my ($ie, $cr, $oe) = map { $e->{$_} // 0 } qw(in_err crc out_err);
        if ($ie || $cr || $oe) {
            emit(sprintf "  [ERRORS] %-36s in_err=%-5d crc=%-5d out_err=%d\n",
                $intf, $ie, $cr, $oe);
            $n_err++;
        }
    }
    for my $intf (sort keys %duplex) {
        if (($duplex{$intf}{duplex} // '') =~ /half/i) {
            emit(sprintf "  [DUPLEX] %-36s %s / %s\n",
                $intf, $duplex{$intf}{duplex}, $duplex{$intf}{speed});
            $n_dup++;
        }
    }
    emit(sprintf "\n  Totals: %d down  |  %d with errors  |  %d half-duplex\n",
        $n_down, $n_err, $n_dup);
}

audit_device($_) for @devices;
close $log_fh if $log_fh;