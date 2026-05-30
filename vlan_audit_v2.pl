#!/usr/bin/perl
use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# vlan_trunk_audit.pl - VLAN Trunk Port Consistency Auditor
#
# Purpose:
#   Audits trunk port VLAN membership on Cisco IOS/IOS-XE switches.
#   Identifies VLANs that are allowed on trunks but not actively forwarding
#   (pruned, STP blocking, or missing from VLAN database). Useful for catching
#   misconfigured trunk pruning lists and orphaned VLANs before they cause
#   black-hole routing issues.
#
# Usage:
#   ./vlan_trunk_audit.pl -h <host> -u <user> -p <pass> [-e <enable_pass>]
#                         [-f <device_file>] [-o <logfile>] [-t <timeout>]
#
# Prerequisites:
#   cpan install Expect
#   SSH must be enabled on target device
#   User must have privilege level 1+ (enable needed for detailed trunk data)
#
# Output:
#   Per-trunk summary: allowed VLANs, active VLANs, inactive (gap) VLANs
#   Exit code 0 = clean, 1 = mismatches found, 2 = connection error
# =============================================================================

my ($host, $username, $password, $enable_pass, $device_file, $logfile);
my $timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'e|enable=s'  => \$enable_pass,
    'f|file=s'    => \$device_file,
    'o|output=s'  => \$logfile,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h <host> -u <user> -p <pass> [-e <enable>] [-f <file>] [-o <log>]\n";

my @devices;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; push @devices, $_ if /\S/ && !/^#/; }
    close $fh;
} elsif ($host) {
    push @devices, $host;
} else {
    die "Specify -h <host> or -f <device_file>\n";
}

die "Username required (-u)\n" unless $username;
die "Password required (-p)\n" unless $password;

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or warn "Cannot open log $logfile: $!\n";
}

sub log_out {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub expand_vlan_range {
    my @vlans;
    for my $token (split /,/, shift) {
        if ($token =~ /^(\d+)-(\d+)$/) { push @vlans, $1..$2; }
        elsif ($token =~ /^\d+$/)       { push @vlans, $token; }
    }
    return @vlans;
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
my $exit_code = 0;

for my $device (@devices) {
    log_out("\n=== $device  [$timestamp] ===\n");

    my $exp = Expect->new();
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${username}\@${device}")) {
        log_out("ERROR: Cannot spawn SSH to $device: $!\n");
        $exit_code = 2;
        next;
    }

    my $logged_in = 0;
    $exp->expect($timeout,
        [ qr/[Pp]assword:/,     sub { $exp->send("$password\n"); exp_continue; } ],
        [ qr/[>#]/,             sub { $logged_in = 1; } ],
        [ qr/Connection refused|No route|timed out/, sub { log_out("ERROR: Connection failed to $device\n"); } ],
        [ timeout => sub { log_out("ERROR: Timeout connecting to $device\n"); } ],
    );

    unless ($logged_in) { $exit_code = 2; next; }

    if ($enable_pass) {
        $exp->send("enable\n");
        $exp->expect($timeout, [ qr/[Pp]assword:/, sub { $exp->send("$enable_pass\n"); exp_continue; } ],
                               [ qr/#/, sub {} ]);
    }

    $exp->send("terminal length 0\n");
    $exp->expect($timeout, qr/[>#]/);

    $exp->send("show interfaces trunk\n");
    my $trunk_output = '';
    $exp->expect($timeout,
        [ qr/[>#]/, sub { $trunk_output = $exp->before(); } ],
        [ timeout => sub { log_out("ERROR: Timeout on show interfaces trunk\n"); } ],
    );

    $exp->send("exit\n");
    $exp->soft_close();

    my (%allowed, %active);
    my $section = '';
    for my $line (split /\n/, $trunk_output) {
        $section = 'allowed'  if $line =~ /VLANs allowed on trunk/i;
        $section = 'active'   if $line =~ /VLANs allowed and active/i;
        $section = ''         if $line =~ /VLANs in spanning/i;

        next unless $line =~ /^(\S+)\s+([\d,\-]+)\s*$/;
        my ($intf, $vlan_str) = ($1, $2);
        if ($section eq 'allowed') { $allowed{$intf} = $vlan_str; }
        elsif ($section eq 'active') { $active{$intf} = $vlan_str; }
    }

    if (!%allowed) {
        log_out("  No trunk ports found (or parse error)\n");
        next;
    }

    for my $intf (sort keys %allowed) {
        my %allowed_set  = map { $_ => 1 } expand_vlan_range($allowed{$intf} // '');
        my %active_set   = map { $_ => 1 } expand_vlan_range($active{$intf}  // '');
        my @inactive = sort { $a <=> $b } grep { !$active_set{$_} } keys %allowed_set;

        my $status = @inactive ? 'MISMATCH' : 'OK';
        $exit_code = 1 if @inactive && $exit_code == 0;
        log_out(sprintf("  %-20s  allowed=%-4d  active=%-4d  status=%s\n",
            $intf, scalar keys %allowed_set, scalar keys %active_set, $status));
        if (@inactive) {
            my $inactive_str = join(',', @inactive[0..($#inactive > 9 ? 9 : $#inactive)]);
            $inactive_str .= '...' if @inactive > 10;
            log_out("    Inactive VLANs: $inactive_str\n");
        }
    }
}

close $log_fh if $log_fh;
exit $exit_code;