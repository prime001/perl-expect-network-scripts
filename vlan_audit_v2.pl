#!/usr/bin/perl
# vlan_trunk_audit.pl - VLAN Trunk Port Consistency Auditor
#
# Purpose:
#   Audits trunk port configurations on Cisco IOS/IOS-XE switches.
#   Cross-references trunk allowed-VLAN lists against the VLAN database
#   to flag: non-default native VLANs, overly permissive trunk configs,
#   and VLANs defined in the database but pruned from all trunks.
#
# Usage:
#   ./vlan_trunk_audit.pl <device_ip> [-u user] [-p pass] [-l logfile]
#   ./vlan_trunk_audit.pl -f devices.txt [-u user] [-p pass] [-l logfile]
#
# Prerequisites:
#   Perl modules: Expect, Getopt::Long   (cpan Expect)
#   SSH access at privilege 15; device must support IOS/IOS-XE trunk CLI.

use strict;
use warnings;
use Expect;
use POSIX qw(strftime);
use Getopt::Long qw(:config no_ignore_case);

my $TIMEOUT = 30;
my $PROMPT  = qr/[>#]\s*$/;
my ($device_file, $logfile, $username, $password);

GetOptions(
    'file|f=s' => \$device_file,
    'log|l=s'  => \$logfile,
    'user|u=s' => \$username,
    'pass|p=s' => \$password,
) or die "Usage: $0 <ip> [-u user] [-p pass] [-l log] | -f devices.txt\n";

my $device = shift @ARGV;
die "Usage: $0 <ip> [-u user] [-p pass] [-l log] | -f devices.txt\n"
    unless $device || $device_file;

$username //= $ENV{NET_USER} // do { print "Username: "; chomp(my $v = <STDIN>); $v };
$password //= $ENV{NET_PASS} // do {
    print "Password: "; system("stty -echo");
    chomp(my $v = <STDIN>); system("stty echo"); print "\n"; $v;
};

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open $logfile: $!";
}

my @hosts = $device_file ? do {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!";
    grep { /\S/ && !/^\s*#/ } <$fh>;
} : ($device);

for my $host (@hosts) {
    chomp $host;
    audit_device($host);
}
close($log_fh) if $log_fh;

sub audit_device {
    my ($host) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    out("\n" . "=" x 62);
    out("Device: $host  |  $ts");
    out("=" x 62);

    my $exp = Expect->new;
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${username}\@${host}")) {
        out("ERROR: spawn failed for $host: $!"); return;
    }

    my $ok = $exp->expect($TIMEOUT,
        [ qr/yes\/no\)?/i,  sub { $exp->send("yes\n");          exp_continue } ],
        [ qr/[Pp]assword:/, sub { $exp->send("$password\n");    exp_continue } ],
        [ $PROMPT,          sub { 1 } ],
        [ 'timeout',        sub { out("ERROR: timeout connecting to $host"); 0 } ],
        [ 'eof',            sub { out("ERROR: EOF on connect to $host");     0 } ],
    );
    unless ($ok) { $exp->hard_close(); return; }

    send_cmd($exp, "terminal length 0");
    my $trunk_raw = send_cmd($exp, "show interfaces trunk");
    my $vlan_raw  = send_cmd($exp, "show vlan brief");
    $exp->send("exit\n"); $exp->soft_close();

    parse_and_report($host, $trunk_raw, $vlan_raw);
}

sub send_cmd {
    my ($exp, $cmd) = @_;
    $exp->send("$cmd\n");
    my $buf = '';
    $exp->expect($TIMEOUT, [ $PROMPT, sub { $buf = $exp->before() } ]);
    return $buf;
}

sub parse_and_report {
    my ($host, $trunk_raw, $vlan_raw) = @_;
    my (%trunks, %vlans_db);
    my $section = '';

    for my $line (split /\n/, $trunk_raw) {
        if ($line =~ /^Port\s+Mode\s+Encapsulation\s+Status\s+Native vlan/i) { $section = 'hdr';     next }
        if ($line =~ /^Port\s+Vlans allowed on trunk/i)                       { $section = 'allowed'; next }
        if ($line =~ /^Port\s+Vlans in spanning/i)                            { $section = 'stp';     next }
        if ($section eq 'hdr'     && $line =~ /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)/)
            { $trunks{$1} = { mode=>$2, encap=>$3, status=>$4, native=>$5 } }
        if ($section eq 'allowed' && $line =~ /^(\S+)\s+(.+)/)
            { $trunks{$1}{allowed} = $2 }
    }

    for my $line (split /\n/, $vlan_raw) {
        $vlans_db{$1} = $2 if $line =~ /^(\d+)\s+(\S+)\s+active/i;
    }

    if (!%trunks) { out("  No trunk ports found."); return; }

    out(sprintf("  %-22s %-8s %-12s %-8s %s", "Interface","Status","Encap","Native","Mode"));
    out("  " . "-" x 56);

    my %carried;
    for my $intf (sort keys %trunks) {
        my $t = $trunks{$intf};
        out(sprintf("  %-22s %-8s %-12s %-8s %s",
            $intf, $t->{status}//'?', $t->{encap}//'?', $t->{native}//'?', $t->{mode}//'?'));
        out("  [WARN] $intf: non-default native VLAN $t->{native}")
            if defined $t->{native} && $t->{native} != 1;
        out("  [WARN] $intf: permits ALL VLANs 1-4094 -- consider pruning")
            if ($t->{allowed}//'') =~ /^1-4094$/;
        expand_range($t->{allowed}//'', \%carried);
    }

    my @orphans = grep { $_ != 1 && !$carried{$_} } sort { $a <=> $b } keys %vlans_db;
    if (@orphans) {
        out("\n  VLANs in DB not carried on any trunk:");
        out("  " . join(", ", @orphans));
    } else {
        out("\n  All active VLANs are carried on at least one trunk.");
    }
    out(sprintf("  Summary: %d trunk(s) | %d VLANs in DB | %d not on any trunk",
        scalar keys %trunks, scalar keys %vlans_db, scalar @orphans));
}

sub expand_range {
    my ($str, $href) = @_;
    for my $chunk (split /,/, $str) {
        $chunk =~ s/\s//g;
        if ($chunk =~ /^(\d+)-(\d+)$/) { $href->{$_}++ for $1..$2 }
        elsif ($chunk =~ /^(\d+)$/)    { $href->{$1}++ }
    }
}

sub out {
    my $msg = shift;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}