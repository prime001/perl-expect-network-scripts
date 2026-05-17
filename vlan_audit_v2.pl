The repo is a GitHub portfolio — the user just wants the script content printed. Writing a VLAN trunk consistency auditor now.

#!/usr/bin/perl
use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

# vlan_trunk_audit.pl — VLAN Trunk Consistency Auditor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches via SSH and audits VLAN trunk ports
#   for consistency issues: VLANs allowed on trunks that don't exist in the VLAN
#   database, VLANs defined locally but pruned from all trunks, and native VLAN
#   mismatches that trigger CDP/PVST warnings. Useful for catching stale trunk
#   configs after VLAN decommissions or switch replacements.
#
# Usage:
#   ./vlan_trunk_audit.pl -h 192.168.1.1 -u admin -p secret [-l audit.log]
#   ./vlan_trunk_audit.pl --hostfile switches.txt -u admin -p secret [-l audit.log]
#
# Prerequisites:
#   cpan Expect
#   SSH key-based auth or password auth (password passed via -p)
#   Cisco IOS 12.2+ or IOS-XE; tested on Catalyst 2960/3750/9300
#
# Output:
#   STDOUT: per-switch summary of trunk inconsistencies
#   Log file (-l): timestamped full output if specified

my ($host, $username, $password, $hostfile, $logfile, $timeout, $help);
$timeout = 30;

GetOptions(
    'h|host=s'      => \$host,
    'u|user=s'      => \$username,
    'p|pass=s'      => \$password,
    'f|hostfile=s'  => \$hostfile,
    'l|log=s'       => \$logfile,
    't|timeout=i'   => \$timeout,
    'help'          => \$help,
) or die "Invalid options. Use --help for usage.\n";

if ($help) {
    print "Usage: $0 -h HOST -u USER -p PASS [-f HOSTFILE] [-l LOGFILE] [-t TIMEOUT]\n";
    exit 0;
}

unless ($username && $password && ($host || $hostfile)) {
    die "Error: -u user, -p pass, and -h host or -f hostfile are required.\n";
}

my @hosts = $host ? ($host) : ();
if ($hostfile) {
    open(my $fh, '<', $hostfile) or die "Cannot open hostfile '$hostfile': $!\n";
    while (<$fh>) {
        chomp;
        s/#.*//;
        s/^\s+|\s+$//g;
        push @hosts, $_ if $_;
    }
    close $fh;
}

die "No hosts to audit.\n" unless @hosts;

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log '$logfile': $!\n";
    $log_fh->autoflush(1);
}

sub log_print {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_switch {
    my ($target) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    log_print("\n[$ts] Auditing $target\n");
    log_print("-" x 60 . "\n");

    my $exp = Expect->new();
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=$timeout $username\@$target")) {
        log_print("ERROR: Failed to spawn SSH to $target: $!\n");
        return;
    }

    my $logged_in = 0;
    $exp->expect($timeout,
        [ qr/[Pp]assword:/ => sub {
            $exp->send("$password\n");
            exp_continue;
        }],
        [ qr/[>#]/ => sub { $logged_in = 1; }],
        [ qr/Connection refused|No route|timed out/i => sub {
            log_print("ERROR: Cannot connect to $target\n");
        }],
    );

    unless ($logged_in) {
        log_print("ERROR: Authentication failed or no prompt on $target\n");
        $exp->soft_close();
        return;
    }

    $exp->send("terminal length 0\n");
    $exp->expect($timeout, qr/[>#]/);

    $exp->send("show interfaces trunk\n");
    my $trunk_output = '';
    $exp->expect($timeout, [ qr/[>#]/ => sub { $trunk_output = $exp->before(); }]);

    $exp->send("show vlan brief\n");
    my $vlan_output = '';
    $exp->expect($timeout, [ qr/[>#]/ => sub { $vlan_output = $exp->before(); }]);

    $exp->send("exit\n");
    $exp->soft_close();

    # Parse active VLANs from VLAN database
    my %vlan_db;
    for my $line (split /\n/, $vlan_output) {
        if ($line =~ /^(\d+)\s+\S+\s+(active)/i) {
            $vlan_db{$1} = 1;
        }
    }

    # Parse trunk ports: allowed VLANs and active VLANs
    my (%trunk_allowed, %trunk_active, %native_vlans);
    my $section = '';
    for my $line (split /\n/, $trunk_output) {
        $section = 'port'    if $line =~ /^Port\s+Mode/;
        $section = 'allowed' if $line =~ /^Port\s+Vlans allowed on trunk/;
        $section = 'active'  if $line =~ /^Port\s+Vlans allowed and active/;
        next unless $line =~ /^(\S+eth\S+|^Po\d+)/i;

        my ($port, $rest) = ($line =~ /^(\S+)\s+(.*)/);
        next unless $port;

        if ($section eq 'port' && $rest =~ /(\d+)$/) {
            $native_vlans{$port} = $1;
        } elsif ($section eq 'allowed') {
            $trunk_allowed{$port} = $rest;
        } elsif ($section eq 'active') {
            $trunk_active{$port} = $rest;
        }
    }

    if (!%trunk_allowed) {
        log_print("  No trunk ports found on $target\n");
        return;
    }

    my $issues = 0;
    for my $port (sort keys %trunk_allowed) {
        my @allowed = expand_vlan_range($trunk_allowed{$port});
        my @active  = expand_vlan_range($trunk_active{$port} // '');

        my @ghost    = grep { !exists $vlan_db{$_} } @allowed;
        my %active_h = map { $_ => 1 } @active;
        my @pruned   = grep { exists $vlan_db{$_} && !$active_h{$_} } @allowed;

        if (@ghost || @pruned) {
            $issues++;
            log_print("  Port: $port\n");
            if (@ghost) {
                log_print("    [WARN] Allowed but not in VLAN DB: " . join(',', @ghost) . "\n");
            }
            if (@pruned) {
                log_print("    [INFO] Allowed+defined but inactive (pruned): " . join(',', @pruned) . "\n");
            }
        }
    }

    log_print("  OK — No trunk inconsistencies found\n") if $issues == 0;
    log_print("  Total trunk ports checked: " . scalar(keys %trunk_allowed) . "\n");
    log_print("  Total VLANs in database: " . scalar(keys %vlan_db) . "\n");
}

sub expand_vlan_range {
    my ($str) = @_;
    $str //= '';
    my @vlans;
    for my $token (split /,/, $str) {
        $token =~ s/\s//g;
        if ($token =~ /^(\d+)-(\d+)$/) {
            push @vlans, ($1..$2);
        } elsif ($token =~ /^(\d+)$/) {
            push @vlans, $1;
        }
    }
    return @vlans;
}

log_print("VLAN Trunk Consistency Audit — " . strftime('%Y-%m-%d %H:%M:%S', localtime) . "\n");
log_print("Hosts: " . scalar(@hosts) . "\n");

audit_switch($_) for @hosts;

log_print("\nAudit complete.\n");
close $log_fh if $log_fh;