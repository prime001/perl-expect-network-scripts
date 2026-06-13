#!/usr/bin/perl
#
# cdp_lldp_neighbors.pl - CDP/LLDP Neighbor Discovery and Topology Mapper
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and collects CDP and LLDP
#   neighbor tables. Useful for topology verification, change auditing, and
#   identifying unknown devices attached to the network.
#
# Usage:
#   Single device:  ./cdp_lldp_neighbors.pl -h 192.168.1.1 [-u admin] [-l out.log]
#   Device file:    ./cdp_lldp_neighbors.pl -f devices.txt [-u admin] [-l out.log]
#
#   Environment: NET_USER and NET_PASS override -u/-p defaults.
#   devices.txt:  one IP/hostname per line; blank lines and # comments ignored.
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH reachability; read-only (privilege 1) credentials sufficient.

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_log);
my $opt_user    = $ENV{NET_USER} // 'admin';
my $opt_pass    = $ENV{NET_PASS} // '';
my $opt_timeout = 30;

GetOptions(
    'h|host=s'     => \$opt_host,
    'f|file=s'     => \$opt_file,
    'u|user=s'     => \$opt_user,
    'p|pass=s'     => \$opt_pass,
    'l|log=s'      => \$opt_log,
    't|timeout=i'  => \$opt_timeout,
) or die "Usage: $0 -h HOST | -f FILE [-u USER] [-p PASS] [-l LOGFILE]\n";

die "Specify -h HOST or -f FILE\n" unless $opt_host || $opt_file;

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open my $fh, '<', $opt_file or die "Cannot open $opt_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*$/ || /^\s*#/; push @devices, $_; }
    close $fh;
}

my $log_fh;
if ($opt_log) {
    open $log_fh, '>>', $opt_log or die "Cannot open log $opt_log: $!\n";
}

sub emit {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub parse_neighbors {
    my ($raw) = @_;
    my (@neighbors, %cur);
    for my $line (split /\n/, $raw) {
        if ($line =~ /^(?:Device ID|System Name):\s*(.+)/i) {
            push @neighbors, {%cur} if %cur;
            %cur = (device => $1 =~ s/\s+$//r);
        } elsif ($line =~ /IP [Aa]ddress:\s*(\S+)/)          { $cur{ip}          //= $1 }
        elsif ($line =~ /Interface:\s*([^,]+),\s*Port ID[^:]*:\s*(.+)/i) {
            $cur{local_if}  = $1 =~ s/\s+$//r;
            $cur{remote_if} = $2 =~ s/\s+$//r;
        }
        elsif ($line =~ /Platform:\s*([^,]+)/i)              { $cur{platform}    = $1 =~ s/\s+$//r }
    }
    push @neighbors, {%cur} if %cur;
    return @neighbors;
}

sub audit_device {
    my ($device) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    emit("\n" . "=" x 62 . "\n");
    emit("Device : $device\nScanned: $ts\n");
    emit("=" x 62 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $opt_user,
        password => $opt_pass,
        timeout  => $opt_timeout,
        raw_pty  => 1,
    );

    my $banner;
    eval { $banner = $ssh->login() };
    if ($@ || !defined $banner) {
        emit("  ERROR: SSH connection failed: $@\n");
        return;
    }
    if ($banner =~ /denied|incorrect|failed/i) {
        emit("  ERROR: Authentication rejected\n");
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('[#>]\s*$', 5);

    my $cur_prompt = $ssh->waitfor('[#>]\s*$', 3) // '';
    if ($cur_prompt =~ />\s*$/) {
        $ssh->send("enable\n");
        my $r = $ssh->waitfor('assword:|#', 5) // '';
        if ($r =~ /assword:/) { $ssh->send("$opt_pass\n"); $ssh->waitfor('#', 5); }
    }

    for my $proto (qw(cdp lldp)) {
        my $PROTO = uc($proto);
        emit("\n-- $PROTO Neighbors --\n");
        $ssh->send("show $proto neighbors detail\n");
        my $out = $ssh->waitfor('#', $opt_timeout) // '';

        if ($out =~ /not enabled|invalid input|% $PROTO/i) {
            emit("  $PROTO is not enabled on this device.\n");
            next;
        }

        my @nbrs = parse_neighbors($out);
        unless (@nbrs) {
            emit("  No $PROTO neighbors detected.\n");
            next;
        }

        emit(sprintf("  %-32s %-16s %-22s %-22s %s\n",
            'Neighbor Device', 'IP Address', 'Local Interface', 'Remote Port', 'Platform'));
        emit("  " . "-" x 100 . "\n");
        for my $n (@nbrs) {
            emit(sprintf("  %-32s %-16s %-22s %-22s %s\n",
                $n->{device}    // 'unknown',
                $n->{ip}        // 'N/A',
                $n->{local_if}  // 'N/A',
                $n->{remote_if} // 'N/A',
                $n->{platform}  // 'N/A',
            ));
        }
        emit("  Total: " . scalar(@nbrs) . " neighbor(s)\n");
    }

    $ssh->close();
}

audit_device($_) for @devices;
emit("\nComplete. Processed " . scalar(@devices) . " device(s).\n");
close $log_fh if $log_fh;