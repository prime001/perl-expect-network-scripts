#!/usr/bin/perl
#
# Script:  029_ntp_check.pl
# Purpose: NTP Compliance Auditor for Cisco IOS/IOS-XE — validates clock offset,
#          stratum level, synchronization state, and authentication across a fleet.
#          Produces a pass/fail compliance report suitable for change-control audits.
#
# Usage:
#   ./029_ntp_check.pl -f hosts.txt [-l audit.log] [--max-stratum 5] [--max-offset 500]
#   ./029_ntp_check.pl 10.0.0.1 10.0.0.2 10.0.0.3
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#   Export NET_USER and NET_PASS before running, or edit the defaults below.
#
# Output columns: Device | Stratum | RefClock | Offset(ms) | Auth | PASS/FAIL
#
# Exit code: 0 = all devices compliant, 1 = one or more failures / errors

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

# --- Defaults (override with env vars or CLI flags) --------------------------
my $USER         = $ENV{NET_USER} // 'admin';
my $PASS         = $ENV{NET_PASS} // '';
my $TIMEOUT      = 15;
my $DEF_STRATUM  = 5;      # compliance ceiling
my $DEF_OFFSET   = 500;    # max acceptable clock offset in milliseconds

# --- CLI Parsing -------------------------------------------------------------
my ($host_file, $log_file, $max_stratum, $max_offset);
GetOptions(
    'f|file=s'        => \$host_file,
    'l|log=s'         => \$log_file,
    'max-stratum=i'   => \$max_stratum,
    'max-offset=f'    => \$max_offset,
) or usage();

$max_stratum //= $DEF_STRATUM;
$max_offset  //= $DEF_OFFSET;

my @devices;
if ($host_file) {
    open my $fh, '<', $host_file or die "Cannot open $host_file: $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
}
push @devices, @ARGV;
usage() unless @devices;

# --- Logging -----------------------------------------------------------------
my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $policy = "stratum<=$max_stratum, offset<${max_offset}ms, synchronized";
out("=== NTP Compliance Audit  $ts  Policy: $policy ===");
out(sprintf "%-22s %-9s %-17s %-12s %-6s %s",
    'Device','Stratum','RefClock','Offset(ms)','Auth','Result');
out('-' x 78);

my ($n_pass, $n_fail) = (0, 0);

for my $host (@devices) {
    my $r = audit($host);
    if ($r->{error}) {
        out(sprintf "%-22s ERROR: %s", $host, $r->{error});
        $n_fail++;
        next;
    }

    my $ok = $r->{synced}
          && $r->{stratum} <= $max_stratum
          && abs($r->{offset}) < $max_offset;

    $ok ? $n_pass++ : $n_fail++;
    out(sprintf "%-22s %-9s %-17s %-12.3f %-6s %s",
        $host,
        $r->{stratum},
        $r->{refclock},
        $r->{offset},
        ($r->{auth} ? 'yes' : 'no'),
        ($ok ? 'PASS' : 'FAIL'));

    unless ($ok) {
        out("  ! NOT synchronized")              unless $r->{synced};
        out("  ! Stratum $r->{stratum} > $max_stratum") if $r->{stratum} > $max_stratum;
        out(sprintf "  ! Offset %.3fms >= ${max_offset}ms", abs($r->{offset}))
            if abs($r->{offset}) >= $max_offset;
    }
}

out('-' x 78);
out(sprintf "Devices: %d  |  PASS: %d  |  FAIL: %d", scalar(@devices), $n_pass, $n_fail);
close $log_fh if $log_fh;
exit($n_fail > 0 ? 1 : 0);

# --- Subroutines -------------------------------------------------------------

sub audit {
    my ($host) = @_;
    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        user       => $USER,
        password   => $PASS,
        raw_pty    => 1,
        timeout    => $TIMEOUT,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=no',
    );

    eval { $ssh->login() };
    return { error => "Auth failed: $@" } if $@;

    $ssh->send('terminal length 0');
    $ssh->waitfor('\#\s*$', 5);

    $ssh->send('show ntp status');
    my $status = $ssh->waitfor('\#\s*$', $TIMEOUT) // '';

    $ssh->send('show ntp associations detail');
    my $detail = $ssh->waitfor('\#\s*$', $TIMEOUT) // '';

    eval { $ssh->close() };

    return parse_ntp($status, $detail);
}

sub parse_ntp {
    my ($status, $detail) = @_;
    my %r = (stratum => 16, refclock => 'none', offset => 0, synced => 0, auth => 0);

    $r{synced}   = 1        if $status =~ /Clock is synchronized/i;
    ($r{stratum})  = ($1)   if $status =~ /stratum\s+(\d+)/i;
    ($r{refclock}) = ($1)   if $status =~ /reference is\s+([\d\.]+)/i;
    ($r{offset})   = ($1)   if $status =~ /clock offset is\s+([\-\d\.]+)\s+m/i;
    $r{auth}     = 1        if $detail =~ /authenticated/i || $detail =~ /Authentication.*enabled/i;

    return \%r;
}

sub out {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}

sub usage {
    die "Usage: $0 [-f hosts_file] [-l log] [--max-stratum N] [--max-offset N] [host...]\n";
}