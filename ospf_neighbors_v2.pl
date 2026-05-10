The repo context in the prompt is a GitHub portfolio repo, not this local project. I'll generate the script content directly.

```perl
#!/usr/bin/perl
# ospf_lsdb_summary.pl - OSPF Link State Database Summarizer
#
# Purpose:
#   Audits the OSPF LSDB on Cisco IOS/IOS-XE routers. Reports LSA counts
#   by type per area, flags excessive external LSAs (possible redistribution
#   leak), NSSA areas, and ASBRs with no matching external LSAs. Complements
#   ospf_neighbors.pl (neighbor state) with database-level visibility.
#
# Usage:
#   Single device:  ./ospf_lsdb_summary.pl <host> <user> <password>
#   Device file:    ./ospf_lsdb_summary.pl -f devices.txt
#
#   Device file format (one per line, whitespace-delimited):
#     <host> <user> <password>
#
# Prerequisites:
#   cpan Net::SSH::Expect
#
# Output:
#   STDOUT + ospf_lsdb_YYYYMMDD_HHMMSS.log

use strict;
use warnings;
use Net::SSH::Expect;
use POSIX qw(strftime);
use Getopt::Long;

my $TIMEOUT      = 20;
my $EXT_LSA_WARN = 500;

my $device_file;
GetOptions('f=s' => \$device_file)
    or die "Usage: $0 [-f devices.txt] [host user password]\n";

my $log_file = "ospf_lsdb_" . strftime("%Y%m%d_%H%M%S", localtime) . ".log";
open(my $LOG, '>', $log_file) or die "Cannot open log $log_file: $!\n";

sub out {
    print @_;
    print $LOG @_;
}

sub collect {
    my ($ssh, $cmd) = @_;
    $ssh->send($cmd);
    my $buf = "";
    while (defined(my $line = $ssh->read_line())) {
        last if $line =~ /^\S+[#>]\s*$/;
        $buf .= "$line\n";
    }
    return $buf;
}

sub audit_device {
    my ($host, $user, $pass) = @_;
    out("\n" . "=" x 62 . "\n");
    out("Host: $host  [" . strftime("%Y-%m-%d %H:%M:%S", localtime) . "]\n");
    out("=" x 62 . "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $host,
            user     => $user,
            password => $pass,
            raw_pty  => 1,
            timeout  => $TIMEOUT,
        );
    };
    if ($@ || !$ssh) { out("CONNECT ERROR: $@\n"); return; }

    eval { $ssh->login() };
    if ($@) { out("AUTH ERROR: $@\n"); return; }

    collect($ssh, "terminal length 0");

    my $proc_out = collect($ssh, "show ip ospf");
    my $db_out   = collect($ssh, "show ip ospf database database-summary");

    $ssh->send("exit");
    eval { $ssh->close() };

    # Parse process header
    my ($pid, $rid)  = ("?", "?");
    $pid = $1 if $proc_out =~ /Routing Process "ospf (\d+)"/;
    $rid = $1 if $proc_out =~ /Router ID(?:\s+is)?\s+([\d.]+)/;

    my $spf_total = 0;
    $spf_total += $1 while $proc_out =~ /SPF algorithm executed (\d+) times/g;

    my $area_count = () = $proc_out =~ /^\s+Area\s+[\d.]+/mg;

    out(sprintf("PID: %-5s  Router-ID: %-16s  Areas: %d  Total SPF runs: %d\n",
        $pid, $rid, $area_count, $spf_total));

    # Parse database-summary LSA counts per area
    my (%lsa, $cur_area);
    for my $line (split /\n/, $db_out) {
        $cur_area = $1 if $line =~ /^\s*Area\s+([\d.]+)/;
        next unless defined $cur_area;
        for my $t (qw(Router Network Summary ASBR External NSSA Opaque)) {
            $lsa{$cur_area}{$t} += $1 if $line =~ /^\s+$t\s+(\d+)/i;
        }
    }

    if (!%lsa) {
        out("No OSPF database-summary data — OSPF may not be running.\n");
        return;
    }

    out(sprintf("\n  %-14s %6s %6s %6s %6s %6s %6s\n",
        "Area", "Router", "Net", "Sum", "ASBR", "Ext", "NSSA"));
    out("  " . "-" x 54 . "\n");

    my @warnings;
    for my $area (sort keys %lsa) {
        my %c = map { $_ => ($lsa{$area}{$_} // 0) }
                qw(Router Network Summary ASBR External NSSA);
        out(sprintf("  %-14s %6d %6d %6d %6d %6d %6d\n",
            $area, @c{qw(Router Network Summary ASBR External NSSA)}));

        push @warnings, "Area $area: $c{External} external LSAs (threshold: $EXT_LSA_WARN)"
            if $c{External} > $EXT_LSA_WARN;
        push @warnings, "Area $area: ASBR LSA present but no external LSAs — check redistribution"
            if $c{ASBR} > 0 && $c{External} == 0;
        push @warnings, "Area $area: NSSA in use — verify stub config is consistent across all ABRs"
            if $c{NSSA} > 0;
    }

    if (@warnings) {
        out("\n  Warnings:\n");
        out("    [!] $_\n") for @warnings;
    } else {
        out("\n  LSDB looks clean — no anomalies detected.\n");
    }
}

# Load device list
my @devices;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp; next if /^\s*[#;]/ || /^\s*$/;
        my @f = split /\s+/, $_, 3;
        push @devices, \@f if @f == 3;
    }
    close $fh;
} elsif (@ARGV == 3) {
    push @devices, [@ARGV[0..2]];
} else {
    die "Usage: $0 <host> <user> <password>\n       $0 -f devices.txt\n";
}

die "No valid device entries found.\n" unless @devices;

audit_device(@$_) for @devices;

out("\nLog written to: $log_file\n");
close $LOG;
```

This script focuses on the OSPF LSDB (`show ip ospf database database-summary`) rather than neighbor state, which is what the existing `ospf_neighbors.pl`/`v2` scripts cover. It catches redistribution leaks (external LSA floods), NSSA/stub misconfigurations, and orphaned ASBR records — practical things a network engineer would actually alert on.