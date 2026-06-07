#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# ospf_db_audit.pl - OSPF Link-State Database consistency checker
#
# Purpose:
#   Connects to one or more IOS/IOS-XE routers and pulls OSPF LSDB summaries.
#   Compares LSA counts across devices within the same area to surface
#   database inconsistencies that neighbor-state checks won't catch
#   (partial sync, stuck LSAs, unexpected external injection).
#
# Usage:
#   ospf_db_audit.pl --host 10.0.0.1 [--host 10.0.0.2 ...] [options]
#   ospf_db_audit.pl --file devices.txt [options]
#
# Options:
#   --host <ip>        Device to audit (repeatable)
#   --file <path>      Newline-separated list of device IPs
#   --user <name>      SSH username (default: admin)
#   --pass <pass>      SSH password (prompt if omitted)
#   --timeout <sec>    Per-command timeout (default: 20)
#   --log <path>       Append results to log file
#   --area <id>        Filter to specific OSPF area (default: all)
#
# Prerequisites:
#   CPAN: Net::SSH::Expect, Getopt::Long
#   Devices must have SSH enabled and 'show ip ospf database' accessible.

my (@hosts, $host_file, $username, $password, $timeout, $log_file, $filter_area);
$username = 'admin';
$timeout  = 20;

GetOptions(
    'host=s'    => \@hosts,
    'file=s'    => \$host_file,
    'user=s'    => \$username,
    'pass=s'    => \$password,
    'timeout=i' => \$timeout,
    'log=s'     => \$log_file,
    'area=s'    => \$filter_area,
) or die "Usage: $0 --host <ip> [--host <ip>...] | --file <path> [--user u] [--pass p] [--timeout n] [--log path] [--area id]\n";

if ($host_file) {
    open my $fh, '<', $host_file or die "Cannot open $host_file: $!";
    while (<$fh>) { chomp; push @hosts, $_ if /\S/ && !/^#/ }
    close $fh;
}
die "No hosts specified. Use --host or --file.\n" unless @hosts;

unless ($password) {
    print "SSH password: ";
    system('stty', '-echo');
    chomp($password = <STDIN>);
    system('stty', 'echo');
    print "\n";
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!";
}

sub output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=== OSPF LSDB Audit: $ts ===\n");

my %area_lsa_counts;  # area -> host -> {router,network,summary,asbr,external,nssa}

for my $host (@hosts) {
    output("\n--- $host ---\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $username,
        password    => $password,
        timeout     => $timeout,
        raw_pty     => 1,
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !$login_output) {
        output("  ERROR: SSH login failed for $host: $@\n");
        next;
    }

    # Disable paging
    $ssh->exec('terminal length 0');

    my $db_output = $ssh->exec('show ip ospf database database-summary');
    unless (defined $db_output) {
        output("  ERROR: Command timeout on $host\n");
        $ssh->close();
        next;
    }

    my ($current_area, $current_proc);
    for my $line (split /\n/, $db_output) {
        if ($line =~ /OSPF Router with ID.*Process (\d+)/) {
            $current_proc = $1;
        }
        if ($line =~ /Area\s+(\S+)\s+database summary/i) {
            $current_area = $1;
            $current_area =~ s/[()]//g;
            next if defined $filter_area && $current_area ne $filter_area;
        }
        next unless defined $current_area;
        next if defined $filter_area && $current_area ne $filter_area;

        if ($line =~ /Router\s+\*?\s+(\d+)/) {
            $area_lsa_counts{$current_area}{$host}{router} = $1;
        } elsif ($line =~ /Network\s+(\d+)/) {
            $area_lsa_counts{$current_area}{$host}{network} = $1;
        } elsif ($line =~ /Summary Net\s+(\d+)/) {
            $area_lsa_counts{$current_area}{$host}{summary} = $1;
        } elsif ($line =~ /Summary ASBR\s+(\d+)/) {
            $area_lsa_counts{$current_area}{$host}{asbr} = $1;
        } elsif ($line =~ /Type-5 Ext\s+(\d+)/) {
            $area_lsa_counts{$current_area}{$host}{external} = $1;
        } elsif ($line =~ /NSSA Ext\s+(\d+)/) {
            $area_lsa_counts{$current_area}{$host}{nssa} = $1;
        }
    }

    for my $area (sort keys %area_lsa_counts) {
        my $h = $area_lsa_counts{$area}{$host} // {};
        output(sprintf "  Area %-10s  Router:%3s  Net:%3s  SumNet:%3s  SumASBR:%3s  Ext5:%3s  NSSA:%3s\n",
            $area,
            $h->{router}   // '-',
            $h->{network}  // '-',
            $h->{summary}  // '-',
            $h->{asbr}     // '-',
            $h->{external} // '-',
            $h->{nssa}     // '-',
        );
    }

    $ssh->exec('exit');
    $ssh->close();
}

output("\n=== Consistency Check ===\n");
my $issues = 0;
for my $area (sort keys %area_lsa_counts) {
    my %by_type;
    for my $host (keys %{$area_lsa_counts{$area}}) {
        for my $type (keys %{$area_lsa_counts{$area}{$host}}) {
            push @{$by_type{$type}}, { host => $host, count => $area_lsa_counts{$area}{$host}{$type} };
        }
    }
    for my $type (sort keys %by_type) {
        my @entries = @{$by_type{$type}};
        next if @entries < 2;
        my %counts = map { $_->{count} => 1 } @entries;
        if (keys %counts > 1) {
            output("  MISMATCH  Area $area  $type LSAs: " .
                join(', ', map { "$_->{host}=$_->{count}" } @entries) . "\n");
            $issues++;
        }
    }
}
output($issues ? "  $issues inconsistency(ies) found.\n" : "  All compared LSA counts match.\n");
output("=== Done ===\n");
close $log_fh if $log_fh;