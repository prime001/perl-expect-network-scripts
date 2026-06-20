No skills apply to this direct content generation task. Writing the script now.

#!/usr/bin/perl
#
# ntp_compliance_audit.pl - NTP Policy Compliance Auditor
#
# PURPOSE:
#   Audits network devices to verify NTP configuration meets policy.
#   Checks that devices synchronize only to approved NTP servers,
#   verifies stratum levels are within acceptable range, and flags
#   devices with excessive clock offset or no synchronization.
#   Produces a per-device PASS/FAIL compliance report.
#
# USAGE:
#   ./ntp_compliance_audit.pl -f devices.txt [-l audit.log] [-u admin] [-p secret]
#   ./ntp_compliance_audit.pl -h 192.168.1.1  [-l audit.log] [-u admin] [-p secret]
#
#   Credentials default to env vars NET_USER / NET_PASS if not supplied.
#
# PREREQUISITES:
#   cpanm Net::SSH::Expect Getopt::Long
#
# DEVICE FILE FORMAT:
#   One IP or hostname per line; lines starting with # are skipped.
#
# POLICY (edit to match your environment):
#   @APPROVED_SERVERS  - only these may be the active reference
#   $MAX_STRATUM       - stratum higher than this value triggers a violation
#   $MAX_OFFSET_MS     - absolute offset (ms) above this triggers a violation

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

# ── Policy ────────────────────────────────────────────────────────────────────
my @APPROVED_SERVERS = ('10.0.1.10', '10.0.1.11', 'ntp1.corp.example.com');
my $MAX_STRATUM      = 5;
my $MAX_OFFSET_MS    = 500;
my $SSH_TIMEOUT      = 15;
# ─────────────────────────────────────────────────────────────────────────────

my ($opt_host, $opt_file, $opt_log, $opt_user, $opt_pass, $opt_help);
$opt_user = $ENV{NET_USER} // 'admin';
$opt_pass = $ENV{NET_PASS} // '';

GetOptions(
    'h|host=s' => \$opt_host,
    'f|file=s' => \$opt_file,
    'l|log=s'  => \$opt_log,
    'u|user=s' => \$opt_user,
    'p|pass=s' => \$opt_pass,
    'help'     => \$opt_help,
) or die "Option error. Try --help.\n";

if ($opt_help || (!$opt_host && !$opt_file)) {
    print "Usage: $0 -f devices.txt|-h host [-l logfile] [-u user] [-p pass]\n";
    exit 0;
}

my $LOG;
if ($opt_log) {
    open($LOG, '>>', $opt_log) or die "Cannot open log '$opt_log': $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
emit("=" x 68);
emit("NTP Compliance Audit  $ts");
emit("Approved NTP: " . join('  ', @APPROVED_SERVERS));
emit("Policy: stratum <= $MAX_STRATUM | offset <= ${MAX_OFFSET_MS} ms");
emit("=" x 68);

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open(my $fh, '<', $opt_file) or die "Cannot open '$opt_file': $!\n";
    while (<$fh>) { chomp; next if /^\s*#/ || /^\s*$/; push @devices, $_; }
    close $fh;
}
die "No devices to audit.\n" unless @devices;

my ($n_pass, $n_fail) = (0, 0);
audit($_) for @devices;

emit("");
emit("=" x 68);
emit(sprintf("Result: %d device(s)  PASS: %d  FAIL: %d",
    scalar @devices, $n_pass, $n_fail));
close $LOG if $LOG;
exit($n_fail ? 1 : 0);

# ── Subroutines ───────────────────────────────────────────────────────────────

sub audit {
    my ($device) = @_;
    emit("\n[Device: $device]");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host       => $device,
            user       => $opt_user,
            password   => $opt_pass,
            raw_pty    => 1,
            timeout    => $SSH_TIMEOUT,
            ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
        $ssh->login();
    };
    if ($@) {
        (my $err = $@) =~ s/\n.*//s;
        emit("  ERROR: SSH failed - $err");
        $n_fail++;
        return;
    }

    $ssh->exec("terminal length 0");
    my $ntp_status = $ssh->exec("show ntp status")       // '';
    my $ntp_assoc  = $ssh->exec("show ntp associations")  // '';
    $ssh->close();

    # Parse NTP status output
    my $synced     = ($ntp_status =~ /Clock is synchronized/i)      ? 1    : 0;
    my $ref_server = ($ntp_status =~ /reference is (\S+)/i)         ? $1   : 'none';
    my $stratum    = ($ntp_status =~ /stratum\s+(\d+)/i)            ? $1   : 0;
    my $offset     = ($ntp_status =~ /offset\s+([\-\d\.]+)\s*msec/i)? $1   : undef;

    # Parse configured peer IPs from associations table (lines with * or +)
    my @peers;
    for (split /\n/, $ntp_assoc) {
        push @peers, $1 if /^[*+~]\S*\s+([\d]{1,3}(?:\.[\d]{1,3}){3}|\S+\.\S+)/;
    }

    # Compliance evaluation
    my @violations;
    push @violations, "Clock NOT synchronized"
        unless $synced;
    push @violations, "Stratum $stratum exceeds policy maximum ($MAX_STRATUM)"
        if $synced && $stratum > $MAX_STRATUM;
    push @violations, "Reference '$ref_server' not in approved server list"
        if $synced && !grep { $_ eq $ref_server } @APPROVED_SERVERS;
    push @violations, sprintf("Offset %.1f ms exceeds threshold (%d ms)", $offset, $MAX_OFFSET_MS)
        if $synced && defined $offset && abs($offset) > $MAX_OFFSET_MS;

    emit(sprintf("  Synchronized : %s",   $synced ? "yes" : "NO"));
    emit(sprintf("  Reference    : %s",   $ref_server));
    emit(sprintf("  Stratum      : %s",   $stratum || 'N/A'));
    emit(sprintf("  Offset       : %s",   defined $offset ? "${offset} ms" : 'N/A'));
    emit(sprintf("  Active peers : %s",   @peers ? join(', ', @peers) : 'none detected'));

    if (@violations) {
        emit("  STATUS       : FAIL");
        emit("    - $_") for @violations;
        $n_fail++;
    } else {
        emit("  STATUS       : PASS");
        $n_pass++;
    }
}

sub emit {
    my ($line) = @_;
    print  "$line\n";
    print $LOG "$line\n" if $LOG;
}