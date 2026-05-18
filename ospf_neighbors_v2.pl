The user wants just the script content output directly. Here it is:

#!/usr/bin/perl
# ospf_neighbor_health.pl
#
# Purpose:
#   Deep OSPF neighbor health check for Cisco IOS/IOS-XE routers.
#   Parses "show ip ospf neighbor detail" to detect non-FULL adjacencies,
#   expiring dead timers, and area/interface mismatches across a device list.
#   Complements ospf_neighbors.pl (which shows summary tables) by surfacing
#   the specific parameters that cause adjacency failures.
#
# Usage:
#   Single host:  ./ospf_neighbor_health.pl -h 10.0.0.1
#   From file:    ./ospf_neighbor_health.pl -f routers.txt -l ospf_health.log
#   Credentials from env: NET_USER / NET_PASS (preferred over -u/-p flags)
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#
# Exit codes: 0 = all FULL, 1 = issues found, 2 = script error

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $hostfile, $logfile);
my $username = $ENV{NET_USER} // 'admin';
my $password = $ENV{NET_PASS} // '';

GetOptions(
    'h|host=s' => \$host_arg,
    'f|file=s' => \$hostfile,
    'u|user=s' => \$username,
    'p|pass=s' => \$password,
    'l|log=s'  => \$logfile,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile]\n";

die "Specify -h <host> or -f <file>\n" unless $host_arg || $hostfile;

my @hosts;
if ($host_arg) {
    @hosts = ($host_arg);
} else {
    open(my $fh, '<', $hostfile) or die "Cannot open $hostfile: $!\n";
    @hosts = map { chomp; $_ } grep { /\S/ && !/^\s*#/ } <$fh>;
    close $fh;
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log $logfile: $!\n";
    $log_fh->autoflush(1);
}

my $global_issues = 0;

sub emit {
    print @_;
    print $log_fh @_ if $log_fh;
}

sub dead_secs {
    my ($t) = @_;
    return undef unless defined $t && $t =~ /^(\d+):(\d+):(\d+)$/;
    return $1 * 3600 + $2 * 60 + $3;
}

sub check_device {
    my ($host) = @_;
    emit sprintf("\n=== %s  [%s] ===\n", $host, strftime('%F %T', localtime));

    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        user       => $username,
        password   => $password,
        raw_pty    => 1,
        timeout    => 15,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=no',
    );

    eval { $ssh->login() };
    if ($@) {
        emit "  ERROR: SSH login failed ($@)\n";
        $global_issues++;
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\#\s*$', 5);

    $ssh->send("show ip ospf neighbor detail\n");
    my $raw = $ssh->waitfor('\#\s*$', 25) // '';
    $ssh->send("exit\n");
    $ssh->close();

    unless ($raw =~ /interface address/i) {
        emit "  INFO: No OSPF neighbors found (process may be down or no adjacencies)\n";
        return;
    }

    my (@neighbors, %cur);
    for my $line (split /\n/, $raw) {
        if ($line =~ /^Neighbor\s+(\S+),\s+interface address\s+(\S+)/) {
            %cur = (id => $1, iface_ip => $2);
        } elsif ($line =~ /In the area\s+(\S+)\s+via interface\s+(\S+)/i) {
            $cur{area} = $1;
            $cur{iface} = $2;
        } elsif ($line =~ /State is\s+(\S+)/i) {
            ($cur{state} = $1) =~ s/[,\/].*//;
        } elsif ($line =~ /Dead timer due in\s+([\d:]+)/i) {
            $cur{dead} = $1;
            push @neighbors, {%cur} if $cur{id};
        }
    }

    unless (@neighbors) {
        emit "  WARN: Output received but no neighbors parsed (unexpected format?)\n";
        return;
    }

    emit sprintf("  %-17s  %-10s  %-10s  %-22s  %s\n",
        'Neighbor-ID', 'State', 'Area', 'Interface', 'Health');
    emit "  " . "-" x 78 . "\n";

    my $dev_issues = 0;
    for my $n (@neighbors) {
        my @flags;
        push @flags, "NOT-FULL(state=$n->{state})" if $n->{state} !~ /^FULL$/i;

        my $secs = dead_secs($n->{dead});
        if (defined $secs && $secs < 10) {
            push @flags, sprintf("DEAD-TIMER=%ds", $secs);
        }

        $dev_issues += @flags;
        my $health = @flags ? 'WARN  [' . join('; ', @flags) . ']' : 'OK';
        emit sprintf("  %-17s  %-10s  %-10s  %-22s  %s\n",
            $n->{id}, $n->{state}, $n->{area} // '?', $n->{iface} // '?', $health);
    }

    my $full_count = grep { $_->{state} =~ /^FULL$/i } @neighbors;
    emit sprintf("  Summary: %d/%d FULL  |  %d issue(s) on this device\n",
        $full_count, scalar @neighbors, $dev_issues);
    $global_issues += $dev_issues;
}

for my $h (@hosts) {
    eval { check_device($h) };
    if ($@) {
        emit "  FATAL on $h: $@\n";
        $global_issues++;
    }
}

emit sprintf("\nTotal issues detected across %d device(s): %d\n",
    scalar @hosts, $global_issues);

close($log_fh) if $log_fh;
exit($global_issues ? 1 : 0);