#!/usr/bin/perl
# =============================================================================
# bgp_prefix_monitor.pl - BGP Neighbor Prefix Count Monitor
#
# Purpose:
#   Connects to IOS/IOS-XE routers via SSH and audits BGP IPv4 unicast prefix
#   counts per neighbor. Flags sessions that are established but receiving zero
#   prefixes, counts below a minimum threshold (e.g. partial table leak), or
#   counts exceeding a maximum threshold (e.g. route table explosion). Useful
#   for NOC dashboards and post-maintenance validation.
#
# Usage:
#   Single device:   perl bgp_prefix_monitor.pl -h 192.168.1.1
#   Device file:     perl bgp_prefix_monitor.pl -f routers.txt
#   With thresholds: perl bgp_prefix_monitor.pl -f routers.txt -m 800000 -x 1000000
#   With log:        perl bgp_prefix_monitor.pl -h 10.0.0.1 -l /var/log/bgp_pfx.log
#
# Prerequisites:
#   cpan Expect
#   SSH key auth recommended. Password via env var BGP_MON_PASS.
#   Account requires privilege level 1 (show access) on target devices.
#
# Device file format: one IP/hostname per line; lines starting with # ignored.
#
# Exit: 0 = all peers within thresholds, 1 = issues found or errors
# =============================================================================

use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_log, $opt_min, $opt_max);
my $opt_user    = $ENV{BGP_MON_USER} || $ENV{USER} || 'admin';
my $opt_pass    = $ENV{BGP_MON_PASS} || '';
my $opt_timeout = 30;

GetOptions(
    'h|host=s'    => \$opt_host,
    'f|file=s'    => \$opt_file,
    'l|log=s'     => \$opt_log,
    'u|user=s'    => \$opt_user,
    'm|min=i'     => \$opt_min,
    'x|max=i'     => \$opt_max,
    't|timeout=i' => \$opt_timeout,
) or die "Usage: $0 -h <host>|-f <file> [-l log] [-u user] [-m min] [-x max]\n";

die "Specify -h <host> or -f <file>\n" unless $opt_host || $opt_file;

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open(my $fh, '<', $opt_file) or die "Cannot open $opt_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*[#\s]/; push @devices, $_; }
    close $fh;
}
die "No devices to process\n" unless @devices;

my $log_fh;
if ($opt_log) {
    open($log_fh, '>>', $opt_log) or die "Cannot open log $opt_log: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
emit("=" x 62);
emit("BGP Prefix Monitor  |  $ts");
emit(sprintf("Thresholds: min=%s  max=%s",
    defined $opt_min ? $opt_min : 'none',
    defined $opt_max ? $opt_max : 'none'));
emit("=" x 62);

my $total_issues = 0;

for my $dev (@devices) {
    emit("\n[Device: $dev]");
    $total_issues += audit_device($dev);
}

emit("\n" . "=" x 62);
emit($total_issues
    ? "RESULT: $total_issues device(s) with issues -- review warnings above"
    : "RESULT: All peers within thresholds -- no action required");
emit("=" x 62);
close $log_fh if $log_fh;
exit($total_issues ? 1 : 0);

# ---------------------------------------------------------------------------

sub audit_device {
    my ($dev) = @_;

    my $exp = Expect->new();
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn('ssh', '-o', 'StrictHostKeyChecking=no',
                               '-o', 'ConnectTimeout=10',
                               '-l', $opt_user, $dev)) {
        emit("  ERROR: spawn failed: $!");
        return 1;
    }

    my $ready = 0;
    $exp->expect($opt_timeout,
        [ qr/[Pp]assword:/         => sub { $exp->send("$opt_pass\n"); exp_continue; } ],
        [ qr/yes\/no/i             => sub { $exp->send("yes\n");        exp_continue; } ],
        [ qr/Connection refused/i  => sub { emit("  ERROR: connection refused"); } ],
        [ qr/[>#]\s*$/             => sub { $ready = 1; } ],
        [ timeout                  => sub { emit("  ERROR: connect timeout"); } ],
    );

    unless ($ready) { $exp->soft_close(); return 1; }

    $exp->send("terminal length 0\n");
    $exp->expect($opt_timeout, qr/[>#]\s*$/);

    $exp->send("show bgp ipv4 unicast summary\n");
    my $raw = '';
    $exp->expect($opt_timeout,
        [ qr/[>#]\s*$/ => sub { $raw = $exp->before(); } ],
        [ timeout      => sub { emit("  ERROR: command timeout"); } ],
    );

    $exp->send("exit\n");
    $exp->soft_close();

    unless ($raw) { emit("  ERROR: no output from device"); return 1; }

    # Parse neighbor table: Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
    my @peers;
    for (split /\n/, $raw) {
        if (/^\s*(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)/) {
            push @peers, { ip => $1, asn => $2, updown => $3, state => $4 };
        }
    }

    if (!@peers) {
        emit("  WARNING: no peers parsed -- BGP may not be configured or output format differs");
        return 1;
    }

    my ($ok, $warn) = (0, 0);
    for my $p (@peers) {
        my ($ip, $asn, $updown, $st) = @{$p}{qw(ip asn updown state)};
        my $note;

        if ($st =~ /^\d+$/) {
            if    ($st == 0)                              { $note = "ZERO prefixes received"; }
            elsif (defined $opt_min && $st < $opt_min)   { $note = "BELOW min ($st < $opt_min)"; }
            elsif (defined $opt_max && $st > $opt_max)   { $note = "EXCEEDS max ($st > $opt_max)"; }
        } else {
            $note = "SESSION $st";
        }

        if ($note) {
            emit(sprintf("  [WARN] %-16s AS%-8s up/dn:%-12s %s", $ip, $asn, $updown, $note));
            $warn++;
        } else {
            emit(sprintf("  [OK]   %-16s AS%-8s up/dn:%-12s prefixes:%s", $ip, $asn, $updown, $st));
            $ok++;
        }
    }

    emit("  Peers: " . scalar(@peers) . " total  |  $ok OK  |  $warn flagged");
    return $warn > 0 ? 1 : 0;
}

sub emit {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}