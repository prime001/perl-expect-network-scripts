```perl
#!/usr/bin/perl
# =============================================================================
# bgp_route_dampening.pl - BGP Route Dampening and Flap Detection Audit
# =============================================================================
# Purpose:
#   Connects to IOS/IOS-XE routers via SSH and audits BGP for dampened routes,
#   peer instability indicators, and prefix count anomalies. Useful for
#   identifying route flap issues before they escalate to full outages.
#
# Usage:
#   ./bgp_route_dampening.pl -h 192.168.1.1 -u admin -p secret
#   ./bgp_route_dampening.pl -f devices.txt -u admin -p secret [-l bgp_damp.log]
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to devices with 'show bgp' privileges
#   devices.txt: one IP/hostname per line, lines starting with # are skipped
#
# Output:
#   Prints dampened prefix count, peer reset history, and flagged anomalies.
#   Exit code 2 if any device shows dampened routes or recent peer resets.
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $logfile, $help);
my $timeout   = 30;
my $issues    = 0;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$file,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'l|log=s'      => \$logfile,
    't|timeout=i'  => \$timeout,
    'help'         => \$help,
) or usage();

usage() if $help || !$user || !$pass || (!$host && !$file);

my @devices;
if ($file) {
    open my $fh, '<', $file or die "Cannot open device file '$file': $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
} else {
    push @devices, $host;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or warn "Cannot open log '$logfile': $! — logging to STDOUT only\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=" x 70);
output("BGP Route Dampening Audit — $ts");
output("=" x 70);

for my $device (@devices) {
    output("\n[*] Connecting to $device ...");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $device,
            user        => $user,
            password    => $pass,
            raw_pty     => 1,
            timeout     => $timeout,
        );
    };
    if ($@ || !$ssh) {
        output("  [ERROR] Failed to create SSH session for $device: $@");
        $issues++;
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !$login) {
        output("  [ERROR] Authentication failed for $device");
        $issues++;
        next;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|#|>', 5);

    # Check for dampened BGP routes
    $ssh->send("show ip bgp dampened-paths\n");
    my $damp_out = $ssh->waitfor('\$|#|>', $timeout);
    my $damp_count = 0;
    $damp_count++ while $damp_out =~ /^\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/mg;

    if ($damp_count > 0) {
        output("  [WARN]  $damp_count dampened prefix(es) found on $device");
        $issues++;
    } else {
        output("  [OK]    No dampened prefixes on $device");
    }

    # Check BGP peer reset counts from summary
    $ssh->send("show ip bgp neighbors | include BGP neighbor|resets\n");
    my $peer_out = $ssh->waitfor('\$|#|>', $timeout);
    my $reset_total = 0;
    while ($peer_out =~ /(\d+)\s+resets/g) {
        $reset_total += $1;
    }

    if ($reset_total > 0) {
        output("  [WARN]  $reset_total cumulative BGP peer reset(s) on $device");
        $issues++;
    } else {
        output("  [OK]    No BGP peer resets recorded on $device");
    }

    # Check prefix counts — flag peers exceeding 80% of max-prefix
    $ssh->send("show ip bgp neighbors | include BGP neighbor|prefixes\n");
    my $prefix_out = $ssh->waitfor('\$|#|>', $timeout);
    my $current_peer = '';
    for my $line (split /\n/, $prefix_out) {
        if ($line =~ /BGP neighbor is (\S+)/) {
            $current_peer = $1;
        }
        if ($line =~ /(\d+) accepted prefixes.*maximum (\d+)/) {
            my ($cur, $max) = ($1, $2);
            my $pct = int(($cur / $max) * 100);
            if ($pct >= 80) {
                output("  [WARN]  Peer $current_peer at ${pct}% of max-prefix ($cur/$max) on $device");
                $issues++;
            }
        }
    }

    $ssh->close();
}

output("\n" . "=" x 70);
output("Audit complete. " . ($issues ? "Issues found: $issues" : "All checks passed."));
output("=" x 70);

close $log_fh if $log_fh;
exit($issues ? 2 : 0);

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}

sub usage {
    print <<'USAGE';
Usage: bgp_route_dampening.pl -u USER -p PASS (-h HOST | -f FILE) [-l LOG] [-t TIMEOUT]

  -h, --host     Single device IP or hostname
  -f, --file     File containing one device per line
  -u, --user     SSH username
  -p, --pass     SSH password
  -l, --log      Optional log file (appended)
  -t, --timeout  SSH timeout in seconds (default: 30)
  --help         Show this help

Exit codes: 0 = clean, 2 = issues found
USAGE
    exit 1;
}
```