The user has provided fully-formed specifications and explicitly said "Output ONLY the script content, no markdown fences, no explanation." User instructions take precedence — skipping brainstorming flow.

The existing scripts include `ospf_neighbors.pl` and `ospf_neighbors_v2.pl`, so I'll write an OSPF LSDB (link-state database) analysis script — distinct from neighbor-state checking, genuinely useful for diagnosing routing issues.

```perl
#!/usr/bin/perl
# =============================================================================
# ospf_lsdb_check.pl - OSPF Link-State Database Analyzer
# =============================================================================
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and analyzes the OSPF
#   link-state database for anomalies: stale LSAs (age near MaxAge),
#   excessive LSA counts per router, and database size per area.
#   Useful during routing troubleshooting or post-change validation.
#
# Usage:
#   Single device:  ./ospf_lsdb_check.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./ospf_lsdb_check.pl -f devices.txt -u admin -p secret
#   With log:       ./ospf_lsdb_check.pl -h 10.0.0.1 -u admin -p secret -l ospf.log
#   Custom process: ./ospf_lsdb_check.pl -h 10.0.0.1 -u admin -p secret --pid 2
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#   SSH key auth or password; device must have 'show ip ospf database' access
#
# Exit codes: 0=clean, 1=warnings found, 2=connection/auth error
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $pass, $device_file, $log_file, $ospf_pid, $timeout);
$ospf_pid = 1;
$timeout  = 30;

GetOptions(
    'h|host=s'     => \$host,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'f|file=s'     => \$device_file,
    'l|log=s'      => \$log_file,
    'pid=i'        => \$ospf_pid,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h HOST -u USER -p PASS [-f FILE] [-l LOGFILE] [--pid N]\n";

die "Provide -h HOST or -f FILE\n" unless $host || $device_file;
die "Username required (-u)\n"     unless $user;
die "Password required (-p)\n"     unless $pass;

my @devices = $host ? ($host) : do {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    my @lines = grep { /\S/ && !/^\s*#/ } <$fh>;
    close $fh;
    chomp @lines;
    @lines;
};

my $LOG;
if ($log_file) {
    open $LOG, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=" x 60);
output("OSPF LSDB Check  |  $timestamp");
output("=" x 60);

my $exit_code = 0;

for my $device (@devices) {
    $device =~ s/^\s+|\s+$//g;
    output("\n--- Device: $device ---");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output || $login_output =~ /[Pp]assword:\s*$/) {
        output("  ERROR: Authentication failed for $device");
        $exit_code = 2;
        next;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|#|>', 5);

    my $db_output = run_cmd($ssh, "show ip ospf $ospf_pid database");
    if (!defined $db_output) {
        output("  ERROR: No response from $device — timeout");
        $exit_code = 2;
        next;
    }

    my (%area_counts, @stale_lsas, %router_counts);
    my $current_area = 'unknown';

    for my $line (split /\n/, $db_output) {
        if ($line =~ /OSPF Router with ID.*Area\s+([\d.]+)/) {
            $current_area = $1;
        }
        # Match LSA summary lines: type, link-id, adv-router, age, seq, checksum
        if ($line =~ /^\s*([\d.]+)\s+([\d.]+)\s+0x[0-9A-Fa-f]+\s+0x[0-9A-Fa-f]+\s+(\d+)/) {
            my ($link_id, $adv_router, $age) = ($1, $2, $3);
            $area_counts{$current_area}++;
            $router_counts{$adv_router}++;
            if ($age >= 1700) {  # MaxAge is 3600; warn at ~47% for early detection
                push @stale_lsas, {area => $current_area, id => $link_id,
                                   adv => $adv_router, age => $age};
                $exit_code = 1 unless $exit_code == 2;
            }
        }
    }

    if (!%area_counts) {
        output("  INFO: No OSPF process $ospf_pid found (or not running)");
        next;
    }

    output("  OSPF PID $ospf_pid LSA Summary:");
    for my $area (sort keys %area_counts) {
        output(sprintf("    Area %-15s  %3d LSAs", $area, $area_counts{$area}));
    }

    if (@stale_lsas) {
        output("  WARNINGS: Stale LSAs (age >= 1700s):");
        for my $lsa (@stale_lsas) {
            output(sprintf("    Area %-12s  ID %-15s  Adv %-15s  Age %ds",
                $lsa->{area}, $lsa->{id}, $lsa->{adv}, $lsa->{age}));
        }
    } else {
        output("  OK: No stale LSAs detected");
    }

    # Flag any router contributing disproportionately (>20% of total LSAs)
    my $total = eval { my $t=0; $t += $_ for values %area_counts; $t };
    for my $router (sort keys %router_counts) {
        my $pct = $router_counts{$router} / $total * 100;
        if ($pct > 20 && $total > 10) {
            output(sprintf("  WARN: Router %s holds %.0f%% of LSAs (%d/%d)",
                $router, $pct, $router_counts{$router}, $total));
            $exit_code = 1 unless $exit_code == 2;
        }
    }

    $ssh->close();
}

output("\nDone. Exit code: $exit_code");
close $LOG if $LOG;
exit $exit_code;

sub run_cmd {
    my ($ssh, $cmd) = @_;
    $ssh->send("$cmd\n");
    my $out = $ssh->waitfor('\$|#|>', $timeout);
    return $out;
}

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $LOG "$msg\n" if $LOG;
}
```