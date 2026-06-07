Permission wasn't granted for the write. Here's the complete script content — paste it directly:

```perl
#!/usr/bin/perl
#
# acl_hit_counter.pl - Cisco IOS/IOS-XE ACL Hit Count Analyzer
#
# Purpose:
#   SSH to a Cisco device, pull 'show ip access-lists', parse hit counts
#   per ACE, and flag unused rules (0 matches) and high-hit rules exceeding
#   a configurable threshold. Useful for ACL cleanup, security audits, and
#   identifying top-traffic rules before making changes.
#
# Usage:
#   perl acl_hit_counter.pl --host <ip/hostname> --user <user> --pass <pass>
#                           [--acl <acl-name>] [--log <logfile>]
#                           [--threshold <N>] [--show-unused]
#
# Options:
#   --host        Device IP or hostname (required)
#   --user        SSH username (required)
#   --pass        SSH password (required)
#   --acl         Specific ACL name to inspect (default: all ACLs)
#   --log         Append output to this file in addition to STDOUT
#   --threshold   Hit count to flag as HIGH-TRAFFIC (default: 1000)
#   --show-unused Include rules with 0 hits in per-ACL detail table
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH enabled on device; account needs privilege level 1+
#
# Example:
#   perl acl_hit_counter.pl --host 10.0.1.1 --user netops --pass s3cr3t \
#       --acl OUTSIDE-IN --log /var/log/acl_audit.log --show-unused

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $pass, $acl_filter, $logfile, $show_unused);
my $threshold = 1000;

GetOptions(
    'host=s'      => \$host,
    'user=s'      => \$user,
    'pass=s'      => \$pass,
    'acl=s'       => \$acl_filter,
    'log=s'       => \$logfile,
    'threshold=i' => \$threshold,
    'show-unused' => \$show_unused,
) or die "See script header for usage.\n";

die "Required: --host, --user, --pass\n" unless $host && $user && $pass;

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $logfh;
if ($logfile) {
    open($logfh, '>>', $logfile) or die "Cannot open log '$logfile': $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $logfh $msg if $logfh;
}

out("=" x 62 . "\n");
out("ACL Hit Count Analysis  |  Device: $host\n");
out("Timestamp: $timestamp\n");
out("=" x 62 . "\n");

my $ssh = Net::SSH::Expect->new(
    host     => $host,
    user     => $user,
    password => $pass,
    timeout  => 20,
    raw_pty  => 1,
);

eval {
    my $banner = $ssh->login();
    die "Auth failed or no prompt returned\n" unless $banner =~ /[>#]/;
};
if ($@) {
    out("ERROR: Cannot connect to $host: $@\n");
    close($logfh) if $logfh;
    exit 1;
}

$ssh->exec("terminal length 0");

my $cmd = $acl_filter ? "show ip access-lists $acl_filter" : "show ip access-lists";
my $raw = $ssh->exec($cmd);
$ssh->close();

unless (defined $raw && $raw =~ /\S/) {
    out("ERROR: No output received for: $cmd\n");
    close($logfh) if $logfh;
    exit 1;
}

# Parse ACL blocks
my (%acls, $cur);
for my $line (split /\n/, $raw) {
    if ($line =~ /^\s*(Standard|Extended)\s+IP\s+access\s+list\s+(\S+)/i) {
        $cur = $2;
        $acls{$cur}{type}  = lc($1);
        $acls{$cur}{rules} = [];
    } elsif ($cur && $line =~ /^\s+(\d+)\s+(permit|deny)\s+(.+?)(?:\s+\((\d+)\s+match(?:es)?\))?\s*$/) {
        push @{$acls{$cur}{rules}}, {
            seq      => $1,
            action   => $2,
            criteria => $3,
            hits     => defined($4) ? int($4) : 0,
        };
    }
}

unless (%acls) {
    out("No ACLs parsed. Device may use named ACLs only, or '$cmd' returned no data.\n");
    out("Raw output:\n$raw\n");
    close($logfh) if $logfh;
    exit 1;
}

my ($total_rules, $total_unused, $total_high) = (0, 0, 0);

for my $name (sort keys %acls) {
    my @rules = @{$acls{$name}{rules}};
    my $type  = $acls{$name}{type};

    my $unused = grep { $_->{hits} == 0 } @rules;
    my $high   = grep { $_->{hits} >= $threshold } @rules;

    out("\nACL: $name  ($type)  Rules: " . scalar(@rules) .
        "  Unused: $unused  High-traffic: $high\n");
    out("-" x 62 . "\n");

    if (@rules && ($show_unused || grep { $_->{hits} > 0 } @rules)) {
        out(sprintf("%-6s %-7s %8s  %s\n", "Seq", "Action", "Hits", "Criteria"));
        out("-" x 62 . "\n");
        for my $r (sort { $b->{hits} <=> $a->{hits} } @rules) {
            next if $r->{hits} == 0 && !$show_unused;
            my $flag = '';
            $flag = ' <<HIGH>>'   if $r->{hits} >= $threshold;
            $flag = ' <<UNUSED>>' if $r->{hits} == 0;
            out(sprintf("%-6s %-7s %8d  %.42s%s\n",
                $r->{seq}, $r->{action}, $r->{hits},
                $r->{criteria}, $flag));
        }
    } else {
        out("  (all rules have 0 hits; use --show-unused to display)\n")
            if !$show_unused && $unused == scalar @rules;
    }

    $total_rules  += scalar @rules;
    $total_unused += $unused;
    $total_high   += $high;
}

out("\n" . "=" x 62 . "\n");
out("Summary\n");
out(sprintf("  ACLs analyzed:       %d\n", scalar keys %acls));
out(sprintf("  Total ACEs:          %d\n", $total_rules));
out(sprintf("  Unused ACEs (0 hits):%d\n", $total_unused));
out(sprintf("  High-traffic ACEs:   %d  (>= $threshold hits)\n", $total_high));
out("=" x 62 . "\n");

if ($logfile) {
    close($logfh);
    print "Output appended to: $logfile\n";
}

exit 0;
```

This is `acl_hit_counter.pl` — covers ACL auditing which none of the existing scripts touch. It:

- Runs `show ip access-lists [name]` via `Net::SSH::Expect`
- Parses every ACE's sequence number, action, criteria, and hit count
- Flags `<<UNUSED>>` (0 hits) and `<<HIGH>>` (>= threshold) rules
- Sorts rules by hit count descending so top-traffic rules surface first
- Outputs a per-ACL table plus a summary, dual-written to STDOUT and an optional log file