```perl
#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# bgp_route_analysis.pl - BGP Route Table Analyzer
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers and analyzes the BGP routing table
#   for operational insights: prefix counts, AS path lengths, origin types,
#   and routes with anomalous attributes. Complements bgp_peers scripts which
#   focus on neighbor state; this script focuses on the route table itself.
#
# Usage:
#   ./bgp_route_analysis.pl -h 192.168.1.1 -u admin -p secret
#   ./bgp_route_analysis.pl -f devices.txt -u admin -p secret -l bgp_routes.log
#   ./bgp_route_analysis.pl -h 10.0.0.1 -u admin -p secret --max-aspath 5
#
# Prerequisites:
#   cpan Net::SSH::Expect
#
# devices.txt format (one IP or hostname per line, # for comments):
#   192.168.1.1
#   10.0.0.254
#   # core-router-1
# =============================================================================

my ($host, $user, $pass, $device_file, $log_file, $max_aspath, $timeout);
$max_aspath = 5;
$timeout    = 30;

GetOptions(
    'h|host=s'       => \$host,
    'f|file=s'       => \$device_file,
    'u|user=s'       => \$user,
    'p|pass=s'       => \$pass,
    'l|log=s'        => \$log_file,
    'max-aspath=i'   => \$max_aspath,
    't|timeout=i'    => \$timeout,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOG] [--max-aspath N]\n";

die "Provide -h HOST or -f FILE\n" unless $host || $device_file;
die "Username (-u) required\n"     unless $user;
die "Password (-p) required\n"     unless $pass;

my @devices;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
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
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub log_output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub analyze_device {
    my ($target) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    log_output("\n[$ts] Connecting to $target\n");
    log_output("=" x 60 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $target,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_output = eval { $ssh->login() };
    if ($@ || !defined $login_output) {
        log_output("  ERROR: Connection failed to $target - $@\n");
        return;
    }

    if ($login_output =~ /password|denied/i) {
        log_output("  ERROR: Authentication failed on $target\n");
        $ssh->close();
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('(#|\$)\s*$', $timeout) or do {
        log_output("  ERROR: No prompt after terminal length 0\n");
        $ssh->close();
        return;
    };

    $ssh->send("show ip bgp summary\n");
    my ($summary) = $ssh->waitfor('(#|\$)\s*$', $timeout);
    unless (defined $summary) {
        log_output("  ERROR: Timeout waiting for BGP summary on $target\n");
        $ssh->close();
        return;
    }

    my ($router_id, $as_number, $total_peers, $up_peers) = ('unknown', 'unknown', 0, 0);
    if ($summary =~ /BGP router identifier ([\d.]+), local AS number (\d+)/i) {
        ($router_id, $as_number) = ($1, $2);
    }
    my @peer_lines = grep { /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s/ } split(/\n/, $summary);
    $total_peers = scalar @peer_lines;
    $up_peers    = grep { /\s+\d+\s*$/ } @peer_lines;

    log_output("  Router ID : $router_id\n");
    log_output("  Local AS  : $as_number\n");
    log_output("  BGP Peers : $total_peers total, $up_peers established\n\n");

    $ssh->send("show ip bgp\n");
    my ($bgp_table) = $ssh->waitfor('(#|\$)\s*$', $timeout + 60);
    unless (defined $bgp_table) {
        log_output("  ERROR: Timeout waiting for BGP table on $target\n");
        $ssh->close();
        return;
    }

    my (%origin_count, @long_paths, $total_prefixes);
    $total_prefixes = 0;

    for my $line (split /\n/, $bgp_table) {
        next unless $line =~ /^\s*[*>isdhRSFf]/;
        $total_prefixes++;

        if ($line =~ /\s+([iIeE?])\s*$/) {
            my $origin = $1;
            $origin_count{i}++ if $origin eq 'i';
            $origin_count{e}++ if lc($origin) eq 'e';
            $origin_count{'?'}++ if $origin eq '?';
        }

        if ($line =~ /((?:\d+\s+){$max_aspath,}[iIeE?])/) {
            my $path_str = $1;
            my @asns = grep { /^\d+$/ } split /\s+/, $path_str;
            if (@asns >= $max_aspath) {
                if ($line =~ /\s+([\d.]+\/\d+)\s/) {
                    push @long_paths, { prefix => $1, length => scalar @asns, path => join(' ', @asns) };
                }
            }
        }
    }

    log_output("  BGP Table Summary:\n");
    log_output(sprintf("    Total prefixes : %d\n", $total_prefixes));
    log_output(sprintf("    IGP origin (i) : %d\n", $origin_count{i}  // 0));
    log_output(sprintf("    EGP origin (e) : %d\n", $origin_count{e}  // 0));
    log_output(sprintf("    Incomplete (?) : %d\n", $origin_count{'?'} // 0));

    if (@long_paths) {
        log_output("\n  Routes with AS-path length >= $max_aspath hops:\n");
        for my $r (sort { $b->{length} <=> $a->{length} } @long_paths) {
            log_output(sprintf("    %-20s  hops=%-3d  path=%s\n",
                $r->{prefix}, $r->{length}, $r->{path}));
        }
    } else {
        log_output("\n  No routes with AS-path >= $max_aspath hops found.\n");
    }

    $ssh->send("exit\n");
    $ssh->close();
    log_output("\n  Done: $target\n");
}

for my $dev (@devices) {
    analyze_device($dev);
}

close $log_fh if $log_fh;
```