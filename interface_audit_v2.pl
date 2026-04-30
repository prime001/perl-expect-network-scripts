#!/usr/bin/perl
# =============================================================================
# stp_audit.pl — Spanning Tree Protocol Topology Audit
# =============================================================================
# Purpose : Audits STP topology on Cisco IOS/IOS-XE switches. Reports root
#           bridge status, port roles/states, and topology change (TCN)
#           activity. Flags instability indicators that precede outages:
#           excessive TCN counts, unexpected blocking ports, and err-disabled
#           STP ports.
#
# Usage   : stp_audit.pl -h <host> [-u user] [-p pass] [-l logfile] [-t sec]
#           stp_audit.pl -f <device_file> [-u user] [-p pass] [-l logfile]
#
# Options : -h  Single device hostname or IP
#           -f  File with one hostname/IP per line (# lines are comments)
#           -u  SSH username  (default: $NET_USER env var, then 'admin')
#           -p  SSH password  (default: $NET_PASS env var)
#           -l  Log file path (default: stp_audit_YYYYMMDD_HHMMSS.log)
#           -t  SSH/expect timeout in seconds (default: 30)
#
# Prereqs : Net::SSH::Expect  — cpanm Net::SSH::Expect
#           Cisco IOS or IOS-XE device with SSH enabled
#           Account needs privilege 1+ (show commands only, no enable needed)
# =============================================================================

use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case bundling);
use POSIX        qw(strftime);
use Net::SSH::Expect;

my $DEFAULT_USER    = $ENV{NET_USER} || 'admin';
my $DEFAULT_TIMEOUT = 30;
my $TCN_WARN_THRESH = 10;

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log, $opt_timeout);
GetOptions(
    'h=s' => \$opt_host,
    'f=s' => \$opt_file,
    'u=s' => \$opt_user,
    'p=s' => \$opt_pass,
    'l=s' => \$opt_log,
    't=i' => \$opt_timeout,
) or usage();

usage() unless $opt_host || $opt_file;

my $user    = $opt_user    || $DEFAULT_USER;
my $pass    = $opt_pass    || $ENV{NET_PASS} || '';
my $timeout = $opt_timeout || $DEFAULT_TIMEOUT;
my $logfile = $opt_log     || 'stp_audit_' . strftime('%Y%m%d_%H%M%S', localtime) . '.log';

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open my $fh, '<', $opt_file or die "Cannot open '$opt_file': $!\n";
    while (<$fh>) { chomp; next if /^\s*$/ || /^#/; push @devices, $_ }
    close $fh;
}
die "No devices to audit.\n" unless @devices;

open my $LOG, '>>', $logfile or die "Cannot open log '$logfile': $!\n";

my $started = strftime('%Y-%m-%d %H:%M:%S', localtime);
log_out("=" x 70 . "\n");
log_out("STP Audit  —  $started\n");
log_out("=" x 70 . "\n");

my ($ok, $fail) = (0, 0);
for my $host (@devices) {
    log_out("\n--- $host ---\n");
    eval { audit_device($host); $ok++ };
    if ($@) {
        (my $err = $@) =~ s/\n$//;
        log_out("[FAIL] $err\n");
        $fail++;
    }
}

log_out("\n" . "=" x 70 . "\n");
log_out("Done. Devices OK: $ok  Failed: $fail  Log: $logfile\n");
close $LOG;
exit($fail ? 1 : 0);

# ---------------------------------------------------------------------------
sub audit_device {
    my ($host) = @_;

    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $user,
        password => $pass,
        raw_pty  => 1,
        timeout  => $timeout,
    );

    my $banner = $ssh->login();
    die "Auth failed or no prompt on $host" unless $banner =~ /[>#]/;

    $ssh->exec('terminal length 0');
    $ssh->exec('terminal width 0');

    my $prompt   = ($banner =~ /(\S+)\s*[>#]\s*$/) ? $1 : $host;
    my $stp_sum  = $ssh->exec('show spanning-tree summary totals');
    my $stp_det  = $ssh->exec('show spanning-tree detail');
    $ssh->close();

    # --- parse summary -------------------------------------------------------
    my $is_root = ($stp_sum =~ /This bridge is the root/i) ? 'YES' : 'NO';

    my ($n_fwd, $n_blk, $n_lis, $n_lrn) = (0, 0, 0, 0);
    if ($stp_sum =~ /(\d+)\s+forwarding/i)  { $n_fwd = $1 }
    if ($stp_sum =~ /(\d+)\s+blocking/i)    { $n_blk = $1 }
    if ($stp_sum =~ /(\d+)\s+listening/i)   { $n_lis = $1 }
    if ($stp_sum =~ /(\d+)\s+learning/i)    { $n_lrn = $1 }

    my $stp_mode = 'unknown';
    if    ($stp_sum =~ /Rapid Spanning Tree/i) { $stp_mode = 'RSTP'  }
    elsif ($stp_sum =~ /Multiple Spanning/i)   { $stp_mode = 'MSTP'  }
    elsif ($stp_sum =~ /Spanning Tree/i)       { $stp_mode = 'STP'   }

    # --- parse detail for TCN and err-disabled -------------------------------
    my (%tcn, @err_dis, @half_dup);
    my $cur_vlan = '';

    for (split /\n/, $stp_det) {
        $cur_vlan = $1 if /^(VLAN\S+)/i;
        if (/number of topology changes\s+(\d+)/i && $cur_vlan) {
            $tcn{$cur_vlan} = ($tcn{$cur_vlan} || 0) + $1;
        }
        push @err_dis,  $1 if /Port\s+(\S+).*err.disabled/i;
        push @half_dup, $1 if /Port\s+(\S+).*half.duplex/i;
    }

    # --- report --------------------------------------------------------------
    log_out(sprintf "Host         : %s (%s)\n", $prompt, $host);
    log_out(sprintf "STP Mode     : %s\n",       $stp_mode);
    log_out(sprintf "Root Bridge  : %s\n",       $is_root);
    log_out(sprintf "Port states  : FWD=%-4d BLK=%-4d LIS=%-4d LRN=%-4d\n",
            $n_fwd, $n_blk, $n_lis, $n_lrn);

    my @high_tcn = map { "$_($tcn{$_})" }
                   grep { $tcn{$_} > $TCN_WARN_THRESH }
                   sort keys %tcn;

    if (@high_tcn) {
        log_out(sprintf "[WARN] High TCN (>%d): %s\n", $TCN_WARN_THRESH, join(', ', @high_tcn));
    } else {
        log_out("TCN Activity : within threshold\n");
    }

    log_out("[WARN] Err-disabled STP ports : " . join(', ', @err_dis)  . "\n") if @err_dis;
    log_out("[WARN] Half-duplex STP ports  : " . join(', ', @half_dup) . "\n") if @half_dup;

    if ($n_lis > 0 || $n_lrn > 0) {
        log_out("[INFO] Ports in transitional state (LIS/LRN) — topology may be converging\n");
    }
}

# ---------------------------------------------------------------------------
sub log_out {
    my ($msg) = @_;
    print $msg;
    print $LOG $msg;
}

sub usage {
    print "Usage: stp_audit.pl -h <host> | -f <file> [-u user] [-p pass] [-l log] [-t sec]\n";
    exit 1;
}