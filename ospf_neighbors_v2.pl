```perl
#!/usr/bin/perl
#
# ospf_route_verify.pl - OSPF Routing Table and Database Verification
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers via SSH and verifies OSPF routing
#   table entries against expected prefixes, checks LSA database health,
#   and flags anomalies such as excessive LSA counts or missing routes.
#   Complements ospf_neighbors.pl (adjacency state) by auditing the actual
#   routing and database layer.
#
# Usage:
#   ospf_route_verify.pl -h <host> [-u <user>] [-p <pass>] [-l <logfile>]
#                        [-e <expected_prefixes_file>] [-t <timeout>]
#   ospf_route_verify.pl -f <device_list_file> [-u <user>] [-p <pass>] [-l <logfile>]
#
# Prerequisites:
#   cpanm Net::SSH::Expect
#   SSH key auth recommended; password auth supported via -p or OSPF_PASS env var
#
# Examples:
#   ospf_route_verify.pl -h 192.168.1.1 -u admin -e expected_routes.txt
#   ospf_route_verify.pl -f routers.txt -u netops -l /var/log/ospf_audit.log
#
# Expected prefixes file: one CIDR prefix per line (e.g., 10.0.0.0/8)
#
# Author: Network Automation Portfolio
# Version: 1.0

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $pass, $logfile, $device_file, $prefix_file, $timeout);
my @devices;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'l|log=s'      => \$logfile,
    'e|expected=s' => \$prefix_file,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile] [-e prefixes] [-t timeout]\n";

$user    //= $ENV{OSPF_USER} // 'admin';
$pass    //= $ENV{OSPF_PASS} // '';
$timeout //= 30;

if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open device file $device_file: $!\n";
    @devices = grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
    close $fh;
} elsif ($host) {
    @devices = ($host);
} else {
    die "Must specify -h <host> or -f <device_file>\n";
}

my @expected_prefixes;
if ($prefix_file) {
    open(my $fh, '<', $prefix_file) or die "Cannot open prefix file $prefix_file: $!\n";
    @expected_prefixes = grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
    close $fh;
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log file $logfile: $!\n";
}

sub log_output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub ts { strftime("[%Y-%m-%d %H:%M:%S]", localtime) }

sub audit_device {
    my ($device) = @_;
    my %result = (host => $device, status => 'ok', issues => []);

    log_output(sprintf "%s Connecting to %s...\n", ts(), $device);

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        ($pass ? (password => $pass) : ()),
        raw_pty     => 1,
        timeout     => $timeout,
    );

    eval {
        my $login = $ssh->login();
        unless ($login =~ /[>#]/) {
            die "Login failed or unexpected prompt: $login\n";
        }
    };
    if ($@) {
        log_output(sprintf "%s ERROR [%s]: %s\n", ts(), $device, $@);
        $result{status} = 'error';
        $result{error}  = $@;
        return \%result;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\s*[>#]', $timeout) or warn "terminal length timeout\n";

    # Collect OSPF routes from routing table
    $ssh->send("show ip route ospf");
    my $route_output = '';
    eval {
        ($route_output) = $ssh->waitfor('\s*[>#]', $timeout);
    };
    if ($@) {
        push @{$result{issues}}, "Timeout collecting OSPF routes";
        $result{status} = 'warn';
    }

    my @ospf_routes = ($route_output =~ /^\s*O\S*\s+([\d.]+\/\d+)/mg);
    $result{route_count} = scalar @ospf_routes;
    log_output(sprintf "%s [%s] OSPF routes in RIB: %d\n", ts(), $device, $result{route_count});

    # Check for expected prefixes
    if (@expected_prefixes) {
        my %learned = map { $_ => 1 } @ospf_routes;
        for my $prefix (@expected_prefixes) {
            unless ($learned{$prefix}) {
                push @{$result{issues}}, "Missing expected prefix: $prefix";
                $result{status} = 'warn';
            }
        }
    }

    # Collect LSA database summary
    $ssh->send("show ip ospf database database-summary");
    my $db_output = '';
    eval {
        ($db_output) = $ssh->waitfor('\s*[>#]', $timeout);
    };

    my %lsa_counts;
    while ($db_output =~ /^\s*(Router|Network|Summary Net|Summary ASBR|Type-7 Ext|External)\s+(\d+)/mg) {
        $lsa_counts{$1} = $2;
    }

    my $total_lsas = 0;
    $total_lsas += $_ for values %lsa_counts;
    $result{total_lsas} = $total_lsas;

    log_output(sprintf "%s [%s] LSA database total: %d\n", ts(), $device, $total_lsas);
    for my $type (sort keys %lsa_counts) {
        log_output(sprintf "%s [%s]   %-20s: %d\n", ts(), $device, $type, $lsa_counts{$type});
    }

    # Flag excessive LSA counts (tunable threshold)
    if ($total_lsas > 5000) {
        push @{$result{issues}}, sprintf("High LSA count (%d) may indicate instability", $total_lsas);
        $result{status} = 'warn';
    }

    # Check external LSA count specifically (Type-5 flood scope)
    my $ext_lsas = $lsa_counts{'External'} // 0;
    if ($ext_lsas > 1000) {
        push @{$result{issues}}, sprintf("Excessive external LSAs (%d) - check redistribution policy", $ext_lsas);
        $result{status} = 'warn';
    }

    # Check OSPF process summary for retransmit queue activity
    $ssh->send("show ip ospf | include Retransmission|SPF|Area");
    my $proc_output = '';
    eval {
        ($proc_output) = $ssh->waitfor('\s*[>#]', $timeout);
    };

    my ($spf_runs) = ($proc_output =~ /Number of SPF calculations\s+(\d+)/i);
    $result{spf_runs} = $spf_runs // 'N/A';
    log_output(sprintf "%s [%s] SPF calculations: %s\n", ts(), $device, $result{spf_runs});

    $ssh->send("exit");
    $ssh->close();

    # Summary
    if (@{$result{issues}}) {
        log_output(sprintf "%s [%s] STATUS: %s - %d issue(s)\n",
            ts(), $device, uc($result{status}), scalar @{$result{issues}});
        log_output(sprintf "%s [%s]   ISSUE: %s\n", ts(), $device, $_)
            for @{$result{issues}};
    } else {
        log_output(sprintf "%s [%s] STATUS: OK\n", ts(), $device);
    }

    return \%result;
}

# Main
log_output(sprintf "%s === OSPF Route/Database Audit - %d device(s) ===\n",
    ts(), scalar @devices);

my @results;
for my $dev (@devices) {
    push @results, audit_device($dev);
}

# Final summary
my ($ok, $warn, $err) = (0, 0, 0);
for my $r (@results) {
    if    ($r->{status} eq 'ok')    { $ok++ }
    elsif ($r->{status} eq 'warn')  { $warn++ }
    else                            { $err++ }
}

log_output(sprintf "\n%s === Summary: %d OK / %d WARN / %d ERROR ===\n",
    ts(), $ok, $warn, $err);

close $log_fh if $log_fh;
exit($err > 0 ? 2 : $warn > 0 ? 1 : 0);
```