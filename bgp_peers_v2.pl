```perl
#!/usr/bin/perl
#
# bgp_prefix_monitor.pl
#
# PURPOSE:
#   Monitor BGP neighbor prefix counts against configurable thresholds.
#   Connects to one or more routers, collects BGP summary output, parses
#   prefix counts per neighbor, and reports peers that are down or have
#   dropped below warning/critical prefix thresholds.  Useful for detecting
#   route withdrawals, session resets, or unexpected route leaks without
#   relying on SNMP polling.
#
# USAGE:
#   Single device:   perl bgp_prefix_monitor.pl -h 192.168.1.1
#   Device list:     perl bgp_prefix_monitor.pl -f devices.txt
#   With thresholds: perl bgp_prefix_monitor.pl -h 10.0.0.1 -w 700000 -c 600000
#   With log file:   perl bgp_prefix_monitor.pl -h 10.0.0.1 -l /var/log/bgp_prefixes.log
#
# PREREQUISITES:
#   Perl modules: Net::SSH::Expect, Getopt::Long, POSIX
#     Install: cpan Net::SSH::Expect
#   SSH key-based auth recommended; password via -p or NET_PASS env var.
#   Router user needs at minimum privilege level 1 (show commands).
#
# EXIT CODES (Nagios-compatible):
#   0 = OK       - all peers Established and within thresholds
#   1 = WARNING  - at least one peer below warning prefix threshold
#   2 = CRITICAL - at least one peer down or below critical threshold
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file);
my $warn_threshold = 0;
my $crit_threshold = 0;
my $timeout        = 30;
my $ssh_port       = 22;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$device_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'w|warn=i'    => \$warn_threshold,
    'c|crit=i'    => \$crit_threshold,
    'l|log=s'     => \$log_file,
    't|timeout=i' => \$timeout,
    'P|port=i'    => \$ssh_port,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-w warn] [-c crit] [-l logfile]\n";

$username //= $ENV{NET_USER} // 'admin';
$password //= $ENV{NET_PASS} // '';

die "Specify -h <host> or -f <file>\n" unless $host || $device_file;

my @devices;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        push @devices, $_ if length $_;
    }
    close $fh;
} else {
    push @devices, $host;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or warn "Cannot open log $log_file: $!\n";
}

sub log_msg {
    my ($msg) = @_;
    my $ts   = strftime('%Y-%m-%d %H:%M:%S', localtime);
    my $line = "[$ts] $msg";
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}

sub check_bgp_prefixes {
    my ($device) = @_;
    my %result = (device => $device, peers => [], errors => []);

    my $ssh = eval {
        Net::SSH::Expect->new(
            host       => $device,
            user       => $username,
            password   => $password,
            raw_pty    => 1,
            timeout    => $timeout,
            ssh_option => "-p $ssh_port -o StrictHostKeyChecking=no -o ConnectTimeout=$timeout",
        );
    };
    if ($@) {
        push @{$result{errors}}, "SSH init failed: $@";
        return \%result;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !$ssh->is_logged_in()) {
        push @{$result{errors}}, "Login failed: " . ($@ // 'auth error');
        return \%result;
    }

    $ssh->exec("terminal length 0");

    # Try show bgp summary first (IOS-XE/NX-OS), fall back to show ip bgp summary (classic IOS)
    my $output = $ssh->exec("show bgp summary");
    if (!defined $output || length($output) < 20) {
        $output = $ssh->exec("show ip bgp summary");
    }
    $ssh->close();

    unless (defined $output && length($output) > 20) {
        push @{$result{errors}}, "No BGP summary output received";
        return \%result;
    }

    # Parse neighbor lines from IOS, IOS-XE, and NX-OS "show bgp summary"
    # Established peer line ends with an integer (prefix count)
    # Non-established peer line ends with a state string (Idle, Active, Connect, etc.)
    for my $line (split /\n/, $output) {
        next unless $line =~ /^\s*(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{4,39})\s+/;
        my @f = grep { length $_ } split /\s+/, $line;
        next if @f < 9;

        my $neighbor = $f[0];
        my $last     = $f[-1];
        my $updown   = $f[-2];

        my $peer = { neighbor => $neighbor };
        if ($last =~ /^\d+$/) {
            $peer->{status}   = 'Established';
            $peer->{prefixes} = int($last);
            $peer->{uptime}   = $updown;
        } else {
            $peer->{status}   = $last;
            $peer->{prefixes} = 0;
            $peer->{uptime}   = 'N/A';
        }
        push @{$result{peers}}, $peer;
    }

    return \%result;
}

my $overall = 0;

for my $device (@devices) {
    log_msg("Checking BGP prefix counts on $device");
    my $result = check_bgp_prefixes($device);

    if (@{$result->{errors}}) {
        log_msg("  ERROR   [$device] $_") for @{$result->{errors}};
        $overall = 2 if $overall < 2;
        next;
    }

    unless (@{$result->{peers}}) {
        log_msg("  INFO    [$device] No BGP neighbors found");
        next;
    }

    for my $peer (@{$result->{peers}}) {
        my ($nbr, $pfx, $status, $up) = @{$peer}{qw(neighbor prefixes status uptime)};

        if ($status ne 'Established') {
            log_msg("  CRITICAL [$device] neighbor=$nbr state=$status prefixes=0 uptime=$up");
            $overall = 2 if $overall < 2;
        } elsif ($crit_threshold && $pfx < $crit_threshold) {
            log_msg("  CRITICAL [$device] neighbor=$nbr prefixes=$pfx below_crit=$crit_threshold uptime=$up");
            $overall = 2 if $overall < 2;
        } elsif ($warn_threshold && $pfx < $warn_threshold) {
            log_msg("  WARNING  [$device] neighbor=$nbr prefixes=$pfx below_warn=$warn_threshold uptime=$up");
            $overall = 1 if $overall < 1;
        } else {
            log_msg("  OK       [$device] neighbor=$nbr prefixes=$pfx uptime=$up");
        }
    }
}

close $log_fh if $log_fh;

my @labels = ('OK', 'WARNING', 'CRITICAL');
log_msg("Result: $labels[$overall]");
exit $overall;
```