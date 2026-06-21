The user wants me to write a Perl script for the portfolio repo. Let me write an ACL audit script — that's distinct from all existing scripts (interface_audit, ntp_check, ospf_neighbors, bgp_peers, vlan_audit, config_backup, log_parser, bulk_ops, inventory_collection, show_commands and all their v2s).

#!/usr/bin/perl
# =============================================================================
# acl_audit.pl -- IP Access-List Hit-Count and Policy Auditor
# =============================================================================
# Purpose:
#   Connects via SSH to one or more Cisco IOS/IOS-XE devices, retrieves all
#   IP access-lists, reports per-ACE hit counts, flags zero-hit entries, and
#   warns about ACLs that lack an explicit deny (implicit permit-all tail).
#   Useful for quarterly security reviews, rule cleanup, and compliance audits.
#
# Usage:
#   Single device:   ./acl_audit.pl -h 192.168.1.1 [-u admin] [-p secret]
#   Device list:     ./acl_audit.pl -f devices.txt [-u admin] [-p secret]
#   With log file:   ./acl_audit.pl -h 10.0.0.1 -o /var/log/acl_audit.log
#
# Prerequisites:
#   cpan Net::SSH::Expect  (or: apt install libnet-ssh-expect-perl)
#   SSH enabled on target device; account with at least 'show' privilege
#   Password via -p flag or NET_DEVICE_PASS environment variable
#
# Output columns:
#   [seq] action  match-spec  (N matches)   -- or --   ** 0 hits **
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_out, $opt_timeout);
$opt_user    = 'admin';
$opt_timeout = 20;

GetOptions(
    'h|host=s'    => \$opt_host,
    'f|file=s'    => \$opt_file,
    'u|user=s'    => \$opt_user,
    'p|pass=s'    => \$opt_pass,
    'o|output=s'  => \$opt_out,
    't|timeout=i' => \$opt_timeout,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-o logfile] [-t secs]\n";

die "ERROR: specify -h <host> or -f <file>\n" unless $opt_host || $opt_file;

$opt_pass //= $ENV{NET_DEVICE_PASS}
    or die "ERROR: password required via -p or NET_DEVICE_PASS env var\n";

my @devices;
if ($opt_host) {
    @devices = ($opt_host);
} else {
    open(my $fh, '<', $opt_file) or die "Cannot open $opt_file: $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
}

my $LOG;
if ($opt_out) {
    open($LOG, '>', $opt_out) or die "Cannot write to $opt_out: $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $LOG $msg if $LOG;
}

sub audit_device {
    my ($host) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);

    out("=" x 64 . "\n");
    out("Host: $host    Timestamp: $ts\n");
    out("=" x 64 . "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host       => $host,
            user       => $opt_user,
            password   => $opt_pass,
            raw_pty    => 1,
            timeout    => $opt_timeout,
            log_stdout => 0,
        );
    };
    if ($@ || !$ssh) {
        out("ERROR: SSH init failed for $host: $@\n\n");
        return;
    }

    my $logged_in = eval { $ssh->login() };
    if ($@ || !$logged_in) {
        out("ERROR: Authentication failed for $host\n\n");
        return;
    }

    $ssh->exec('terminal length 0');

    my $raw = eval { $ssh->exec('show ip access-lists') };
    if ($@ || !$raw) {
        out("ERROR: No output from 'show ip access-lists' on $host\n\n");
        $ssh->close();
        return;
    }

    $ssh->exec('exit');
    $ssh->close();

    # ---- parse ----
    my ($acl_name, %has_deny, $acl_count, $ace_count, $zero_count) = ('', (), 0, 0, 0);

    for my $line (split /\n/, $raw) {
        $line =~ s/\r//g;
        next if $line =~ /^\s*$/;
        next if $line =~ /^show ip/i;   # strip echoed command

        if ($line =~ /^(?:Extended|Standard)\s+IP\s+access\s+list\s+(\S+)/i) {
            $acl_name = $1;
            $acl_count++;
            $has_deny{$acl_name} //= 0;
            out("\n  ACL: $acl_name\n");
            next;
        }

        next unless $acl_name;

        # IOS lines: "    10 permit tcp ..." or "    deny any (5 matches)"
        if ($line =~ /^\s+(\d+\s+)?(permit|deny)\s+(.+?)\((\d+)\s+match/i) {
            my ($seq, $action, $spec, $hits) = ($1 // '', lc($2), $3, $4);
            $seq =~ s/\s+$//;
            $has_deny{$acl_name} = 1 if $action eq 'deny';
            $ace_count++;
            $spec =~ s/\s+$//;
            if ($hits == 0) {
                $zero_count++;
                out(sprintf("    %-4s %-6s %s  ** 0 hits **\n", $seq, $action, $spec));
            } else {
                out(sprintf("    %-4s %-6s %s  (%d matches)\n", $seq, $action, $spec, $hits));
            }
        } elsif ($line =~ /^\s+(\d+\s+)?(permit|deny)\s+(.+)/i) {
            # ACE with no match counter yet (counter at 0 not shown on some IOS)
            my ($seq, $action, $spec) = ($1 // '', lc($2), $3);
            $seq =~ s/\s+$//;
            $has_deny{$acl_name} = 1 if $action eq 'deny';
            $ace_count++;
            $zero_count++;
            $spec =~ s/\s+$//;
            out(sprintf("    %-4s %-6s %s  ** 0 hits **\n", $seq, $action, $spec));
        }
    }

    my @no_deny = sort grep { !$has_deny{$_} } keys %has_deny;

    out("\n--- Summary: $host ---\n");
    out("  ACLs audited    : $acl_count\n");
    out("  Total ACEs      : $ace_count\n");
    out("  Zero-hit ACEs   : $zero_count\n");
    if (@no_deny) {
        out("  No explicit deny: " . join(', ', @no_deny)
          . "  [implicit permit-all at tail]\n");
    } else {
        out("  Explicit deny   : present in all ACLs\n");
    }
    out("\n");
}

my $start = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("ACL Audit Report  --  $start\n\n");

for my $dev (@devices) {
    $dev =~ s/^\s+|\s+$//g;
    audit_device($dev);
}

out("Audit complete.  Devices checked: " . scalar(@devices) . "\n");
close($LOG) if $LOG;