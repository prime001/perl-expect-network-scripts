#!/usr/bin/perl
# =============================================================================
# acl_audit.pl — Access Control List Audit Tool
# =============================================================================
# Purpose : SSH into one or more Cisco IOS/IOS-XE devices, enumerate all
#           named and numbered ACLs, map each ACL to its interface bindings
#           (inbound/outbound), and flag common misconfigurations:
#             • ACL unbound — defined but not applied to any interface
#             • Broad permit — "permit any any" present in an extended ACL
#             • Empty ACL — defined with zero entries
#
# Usage   : ./acl_audit.pl -h <host> [options]
#           ./acl_audit.pl -f devices.txt [options]
#
# Options :
#   -h <host>    Single device IP or hostname
#   -f <file>    File containing one device per line (# comments ok)
#   -u <user>    SSH username          (default: admin)
#   -p <pass>    SSH password          (prompted if omitted)
#   -e <secret>  Enable secret         (prompted if omitted)
#   -o <file>    Log file path         (default: acl_audit_YYYYMMDD_HHMMSS.log)
#   -t <secs>    Per-command timeout   (default: 30)
#
# Prerequisites (CPAN):
#   Net::SSH::Expect   Getopt::Long   Term::ReadKey
#
# Tested against : Cisco IOS 15.x, IOS-XE 16.x/17.x
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX       qw(strftime);
use Term::ReadKey;

# ── argument parsing ─────────────────────────────────────────────────────────
my ($opt_host, $opt_file, $opt_log, $opt_timeout);
my ($opt_user, $opt_pass, $opt_enable) = ('admin', undef, undef);

GetOptions(
    'h=s' => \$opt_host,
    'f=s' => \$opt_file,
    'u=s' => \$opt_user,
    'p=s' => \$opt_pass,
    'e=s' => \$opt_enable,
    'o=s' => \$opt_log,
    't=i' => \$opt_timeout,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-e enable] [-o log] [-t secs]\n";

die "Specify -h <host> or -f <file>\n" unless $opt_host || $opt_file;
$opt_timeout //= 30;

unless (defined $opt_pass) {
    print 'SSH password: ';
    ReadMode('noecho');
    chomp($opt_pass = <STDIN>);
    ReadMode('restore');
    print "\n";
}
unless (defined $opt_enable) {
    print 'Enable secret: ';
    ReadMode('noecho');
    chomp($opt_enable = <STDIN>);
    ReadMode('restore');
    print "\n";
}

my $ts = strftime('%Y%m%d_%H%M%S', localtime);
$opt_log //= "acl_audit_$ts.log";
open(my $log, '>', $opt_log) or die "Cannot open $opt_log: $!\n";

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open(my $fh, '<', $opt_file) or die "Cannot open $opt_file: $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if /\S/; }
    close $fh;
}

# ── helpers ──────────────────────────────────────────────────────────────────
my ($total_acls, $total_issues, $ok_count, $fail_count) = (0, 0, 0, 0);

sub tee { print $_[0]; print $log $_[0]; }

sub ssh_cmd {
    my ($ssh, $cmd) = @_;
    $ssh->send($cmd);
    return $ssh->waitfor('#', $opt_timeout) // '';
}

# ── per-device audit ─────────────────────────────────────────────────────────
sub audit_device {
    my ($dev) = @_;
    tee("\n" . ('=' x 62) . "\nDevice: $dev\n" . ('=' x 62) . "\n");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $dev,
            user     => $opt_user,
            password => $opt_pass,
            raw_pty  => 1,
            timeout  => $opt_timeout,
        );
        my $seen = $ssh->login();
        die "Auth rejected\n" if $seen =~ /denied|fail|incorrect/i;

        if ($ssh->before() =~ />\s*$/ || $seen =~ />\s*$/) {
            $ssh->send("enable");
            $ssh->waitfor('Password:', 5) or die "No enable prompt\n";
            $ssh->send($opt_enable);
            $ssh->waitfor('#', 10)        or die "Enable failed\n";
        }
        ssh_cmd($ssh, "terminal length 0");
    };
    if ($@) { tee("  ERROR: $@"); $fail_count++; eval { $ssh->close() }; return; }

    my $acl_out = ssh_cmd($ssh, "show ip access-lists");
    my $int_out = ssh_cmd($ssh, "show ip interface | include line protocol|Inbound|Outbound");
    $ssh->send("exit"); eval { $ssh->close() };

    # parse ACLs
    my (%acls, $cur);
    for (split /\n/, $acl_out) {
        s/\r//g;
        if (/^(Standard|Extended)\s+IP\s+access\s+list\s+(\S+)/i) {
            $cur = $2;
            $acls{$cur} = { type => lc($1), entries => [] };
        } elsif ($cur && /^\s+\d+/) {
            push @{$acls{$cur}{entries}}, $_;
        }
    }

    # parse interface bindings
    my (%bind, $cur_if);
    for (split /\n/, $int_out) {
        s/\r//g;
        $cur_if = $1 if /^(\S+)\s+is\s+\w+,\s+line\s+protocol/;
        push @{$bind{$1}{in}},  $cur_if if $cur_if && /Inbound access list is (?!not set)(\S+)/;
        push @{$bind{$1}{out}}, $cur_if if $cur_if && /Outbound access list is (?!not set)(\S+)/;
    }

    if (!%acls) { tee("  No ACLs defined on this device.\n"); $ok_count++; return; }

    my $dev_issues = 0;
    for my $name (sort keys %acls) {
        $total_acls++;
        my ($type, $entries) = ($acls{$name}{type}, $acls{$name}{entries});
        my @in  = @{$bind{$name}{in}  // []};
        my @out = @{$bind{$name}{out} // []};

        tee(sprintf "\n  ACL %-28s [%-8s %2d entries]\n", $name, $type, scalar @$entries);
        tee("    Inbound:  " . (@in  ? join(', ', @in)  : '(none)') . "\n");
        tee("    Outbound: " . (@out ? join(', ', @out) : '(none)') . "\n");

        my @issues;
        push @issues, "UNBOUND — not applied to any interface"
            unless @in || @out;
        push @issues, "EMPTY — no ACL entries defined"
            unless @$entries;
        push @issues, "BROAD PERMIT — 'permit any any' found"
            if grep { /permit\s+any\s+any/i } @$entries;

        if (@issues) {
            tee("    [!] $_\n") for @issues;
            $dev_issues += @issues;
            $total_issues += @issues;
        } else {
            tee("    [ok]\n");
        }
    }
    tee("\n  Device summary: " . scalar(keys %acls) . " ACL(s), $dev_issues issue(s)\n");
    $ok_count++;
}

# ── main ─────────────────────────────────────────────────────────────────────
tee("ACL Audit Report — $ts\n");
tee("Devices targeted: " . scalar(@devices) . "\n");

audit_device($_) for @devices;

tee("\n" . ('=' x 62) . "\n");
tee("SUMMARY\n");
tee("  Devices audited : $ok_count\n");
tee("  Devices failed  : $fail_count\n");
tee("  Total ACLs found: $total_acls\n");
tee("  Total issues    : $total_issues\n");
tee("  Log written to  : $opt_log\n");
close $log;