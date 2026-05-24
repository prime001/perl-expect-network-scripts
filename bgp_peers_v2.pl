```perl
#!/usr/bin/perl
# =============================================================================
# bgp_prefix_limits.pl - BGP Prefix Limit Monitor
#
# PURPOSE:
#   Connects to Cisco IOS/IOS-XE routers and checks BGP neighbor prefix counts
#   against configured maximum-prefix limits. Flags peers approaching or
#   exceeding thresholds before the router tears down the session.
#
# USAGE:
#   Single device:  ./bgp_prefix_limits.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./bgp_prefix_limits.pl -f devices.txt -u admin -p secret
#   With log:       ./bgp_prefix_limits.pl -h 10.0.0.1 -u admin -p secret -l bgp_check.log
#   Custom warn%:   ./bgp_prefix_limits.pl -h 10.0.0.1 -u admin -p secret -w 70
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   SSH access to devices with 'show bgp' privilege
#
# OUTPUT:
#   Per-peer status: neighbor IP, AS, prefix count, limit, % used, status
#   Status levels: OK | WARN (>80% by default) | CRITICAL (>95%) | OVER_LIMIT
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $device_file, $username, $password, $log_file, $warn_pct);
$warn_pct = 80;

GetOptions(
    'h|host=s'     => \$host_arg,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$log_file,
    'w|warn=i'     => \$warn_pct,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOG] [-w WARN_PCT]\n";

die "Specify -h HOST or -f FILE\n" unless $host_arg || $device_file;
die "Username required (-u)\n" unless $username;
die "Password required (-p)\n" unless $password;

my @devices = $host_arg ? ($host_arg) : do {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
};

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);

sub output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

output("=" x 72 . "\n");
output("BGP Prefix Limit Check - $timestamp\n");
output("Warn threshold: ${warn_pct}%\n");
output("=" x 72 . "\n\n");

for my $host (@devices) {
    output("Device: $host\n");
    output("-" x 50 . "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $host,
            user        => $username,
            password    => $password,
            raw_pty     => 1,
            timeout     => 15,
        );
    };
    if ($@ || !$ssh) {
        output("  ERROR: Failed to create SSH session: $@\n\n");
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !$login) {
        output("  ERROR: Authentication failed or connection refused\n\n");
        next;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\#', 5);

    $ssh->send("show bgp all neighbors | include BGP neighbor|Prefixes Current|maximum-prefix\n");
    my $raw = $ssh->waitfor('\#', 30);

    unless ($raw) {
        output("  ERROR: Timeout waiting for BGP output\n\n");
        $ssh->close();
        next;
    }

    my (%neighbors, $current_peer);
    for my $line (split /\n/, $raw) {
        if ($line =~ /BGP neighbor is (\S+),\s+remote AS (\d+)/) {
            $current_peer = $1;
            $neighbors{$current_peer}{as} = $2;
        }
        if ($current_peer && $line =~ /Prefixes Current:\s+(\d+)/) {
            $neighbors{$current_peer}{prefixes} = $1;
        }
        if ($current_peer && $line =~ /maximum-prefix\s+(\d+)/) {
            $neighbors{$current_peer}{limit} //= $1;
        }
    }

    if (!%neighbors) {
        output("  No BGP neighbors found or BGP not configured\n\n");
        $ssh->close();
        next;
    }

    my $fmt = "  %-18s %-8s %8s %8s %6s  %s\n";
    output(sprintf($fmt, "Neighbor", "AS", "Prefixes", "Limit", "Used%", "Status"));
    output("  " . "-" x 60 . "\n");

    for my $peer (sort keys %neighbors) {
        my $pfx   = $neighbors{$peer}{prefixes} // 0;
        my $limit = $neighbors{$peer}{limit};
        my ($pct_str, $status);

        if ($limit && $limit > 0) {
            my $pct = ($pfx / $limit) * 100;
            $pct_str = sprintf("%.1f%%", $pct);
            if    ($pfx >= $limit)    { $status = "OVER_LIMIT" }
            elsif ($pct >= 95)        { $status = "CRITICAL"   }
            elsif ($pct >= $warn_pct) { $status = "WARN"       }
            else                      { $status = "OK"         }
        } else {
            $pct_str = "N/A";
            $status  = "NO_LIMIT";
            $limit   = "none";
        }

        output(sprintf($fmt,
            $peer,
            $neighbors{$peer}{as} // "?",
            $pfx,
            $limit,
            $pct_str,
            $status
        ));
    }

    $ssh->send("exit\n");
    $ssh->close();
    output("\n");
}

output("Check complete: $timestamp\n");
close($log_fh) if $log_fh;
```