#!/usr/bin/perl
# =============================================================================
# stp_audit.pl — Spanning Tree Protocol Topology Auditor
# =============================================================================
# Purpose:
#   SSHes into Cisco IOS/IOS-XE switches and audits STP state across all
#   active VLANs. Reports root bridge placement, blocking/discarding ports,
#   and topology change counts. Flags conditions that commonly precede
#   bridging loops or unplanned outages.
#
# Usage:
#   ./stp_audit.pl 10.0.0.1
#   ./stp_audit.pl --file switches.txt --user admin --logdir /tmp/stp
#   NET_USER=admin NET_PASS=secret ./stp_audit.pl core-sw-01
#
# Prerequisites:
#   Expect    (cpan install Expect)
#   OpenSSH   client in PATH
#
# Options:
#   <host>         Single device IP or hostname (positional)
#   --file FILE    Newline-delimited device list (lines starting with # ignored)
#   --user USER    SSH username (env NET_USER or interactive prompt)
#   --pass PASS    SSH password (env NET_PASS or interactive prompt)
#   --logdir DIR   Write raw show output per device into this directory
#   --timeout N    Expect timeout in seconds (default 30)
# =============================================================================

use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX       qw(strftime);

my ($file, $logdir, $user, $pass, $help);
my $timeout = 30;

GetOptions(
    'file=s'    => \$file,
    'logdir=s'  => \$logdir,
    'user=s'    => \$user,
    'pass=s'    => \$pass,
    'timeout=i' => \$timeout,
    'help|h'    => \$help,
) or die "Option error. Run with --help for usage.\n";

if ($help) {
    print "Usage: $0 [HOST] [--file F] [--user U] [--pass P] [--logdir D] [--timeout N]\n";
    exit 0;
}

my $host = shift @ARGV;
die "Error: specify a host argument or --file\n" unless $host || $file;

$user //= $ENV{NET_USER} // do {
    local $| = 1; print "Username: "; chomp(my $u = <STDIN>); $u
};
$pass //= $ENV{NET_PASS} // do {
    local $| = 1; print "Password: ";
    system('stty -echo 2>/dev/null'); chomp(my $p = <STDIN>);
    system('stty echo 2>/dev/null');  print "\n"; $p
};

my @targets = $file
    ? do { open my $fh, '<', $file or die "Cannot open $file: $!\n";
           map  { chomp; $_ }
           grep { /\S/ && !/^\s*#/ } <$fh> }
    : ($host);

my $stamp    = strftime('%Y%m%d_%H%M%S', localtime);
my $any_warn = 0;

for my $dev (@targets) {
    printf "\n%s\n  Device: %-38s  %s\n%s\n",
        '=' x 60, $dev, strftime('%H:%M:%S', localtime), '=' x 60;

    my ($raw, $err) = ssh_cmd($dev, $user, $pass, $timeout,
        'terminal length 0',
        'show spanning-tree',
    );

    if ($err) {
        print "  ERROR: $err\n";
        $any_warn = 1;
        next;
    }

    if ($logdir && -d $logdir) {
        (my $safe = $dev) =~ s/[^\w.-]/_/g;
        my $lf = "$logdir/stp_${safe}_${stamp}.log";
        if (open my $lfh, '>', $lf) { print $lfh $raw; close $lfh; print "  Log: $lf\n" }
        else                        { warn "  Cannot write log $lf: $!\n" }
    }

    my @issues = parse_and_report($raw);
    $any_warn = 1 if @issues;
}

exit $any_warn ? 1 : 0;

# ─── Subroutines ─────────────────────────────────────────────────────────────

sub ssh_cmd {
    my ($host, $user, $pass, $timeout, @cmds) = @_;

    my $exp = Expect->new();
    $exp->log_stdout(0);
    $exp->raw_pty(1);

    $exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${user}\@${host}")
        or return (undef, "spawn failed: $!");

    my $ok = $exp->expect($timeout,
        [ qr/[Pp]assword[^:]*:/,               sub { $exp->send("$pass\n"); exp_continue } ],
        [ qr/yes\/no\)?[^\n]*/i,               sub { $exp->send("yes\n");   exp_continue } ],
        [ qr/[>#]/,                             sub { 1 } ],
        [ qr/(?:refused|unreachable|timed out)/i, sub { 0 } ],
        [ 'timeout',                            sub { 0 } ],
    );
    return (undef, "login failed or host unreachable") unless $ok;

    my $output = '';
    for my $cmd (@cmds) {
        $exp->send("$cmd\n");
        $exp->expect($timeout, qr/[>#]/) or return (undef, "timeout waiting for prompt after: $cmd");
        $output .= $exp->before() // '';
    }
    $exp->send("exit\n");
    $exp->soft_close();
    return ($output, undef);
}

sub parse_and_report {
    my ($raw)  = @_;
    my (%vlans, $cur, @issues);

    for my $line (split /\n/, $raw) {
        if ($line =~ /^(?:VLAN|MST)(\d+)\s*$/) {
            $cur = $1;
            $vlans{$cur} = { is_root => 0, blocking => 0, topo_chg => 0 };
        }
        next unless defined $cur;
        my $v = $vlans{$cur};
        $v->{is_root}  = 1  if $line =~ /This bridge is the root/;
        $v->{topo_chg} = $1 if $line =~ /topology changes?\s+(\d+)/i;
        $v->{blocking}++    if $line =~ /\b(?:BLK|DISC|discarding)\b/;
    }

    unless (%vlans) {
        print "  No STP VLAN instances found (STP disabled or unrecognised format)\n";
        return ();
    }

    my $total = scalar keys %vlans;
    my $root  = grep { $vlans{$_}{is_root} } keys %vlans;
    printf "  VLANs tracked : %d    Root bridge for: %d\n", $total, $root;

    for my $vid (sort { $a <=> $b } keys %vlans) {
        my $v = $vlans{$vid};
        if ($v->{blocking}) {
            printf "  [WARN] VLAN %-5s  %d blocking/discarding port(s)\n", $vid, $v->{blocking};
            push @issues, "VLAN $vid: blocking ports";
        }
        if ($v->{topo_chg} > 50) {
            printf "  [WARN] VLAN %-5s  high topology change count: %d\n", $vid, $v->{topo_chg};
            push @issues, "VLAN $vid: excessive topo changes ($v->{topo_chg})";
        }
    }

    print "  Status: OK — no STP anomalies detected\n" unless @issues;
    return @issues;
}