#!/usr/bin/perl
#
# vlan_trunk_audit.pl - VLAN Trunk Pruning & Utilization Auditor
#
# Purpose:
#   SSH into Cisco IOS switches and audit trunk port VLAN configurations.
#   Reports per-trunk utilization, VLANs that are allowed but inactive
#   (pruning candidates), and allowed VLANs absent from the VLAN database.
#   Useful for identifying trunk bloat prior to VLAN cleanup operations.
#
# Usage:
#   ./vlan_trunk_audit.pl <device_ip> [username]
#   ./vlan_trunk_audit.pl --file devices.txt [--log output.log]
#
# Prerequisites:
#   SWITCH_PASS env var must be set (password auth)
#   SWITCH_USER env var optional (default: admin)
#   cpanm Net::SSH::Expect Getopt::Long
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config pass_through);
use POSIX qw(strftime);

my $username = $ENV{SWITCH_USER} // 'admin';
my $password = $ENV{SWITCH_PASS} or die "Error: SWITCH_PASS env var not set\n";
my $timeout  = 20;
my ($file_opt, $log_file, $log_fh);

GetOptions('file=s' => \$file_opt, 'log=s' => \$log_file);

if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log '$log_file': $!\n";
}

sub out {
    print @_;
    print $log_fh @_ if $log_fh;
}

sub expand_vlans {
    my ($str) = @_;
    my @vlans;
    for my $seg (split /,/, $str) {
        if ($seg =~ /^(\d+)-(\d+)$/) { push @vlans, ($1..$2) }
        elsif ($seg =~ /^(\d+)$/)    { push @vlans, $1 }
    }
    return @vlans;
}

sub audit_device {
    my ($host) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);

    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        user       => $username,
        password   => $password,
        raw_pty    => 1,
        timeout    => $timeout,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    my $banner;
    eval { $banner = $ssh->login() };
    if ($@ or $banner !~ /[>#]/) {
        out("[$ts] ERROR $host: login failed - " . ($@ || 'no prompt received') . "\n");
        return;
    }

    $ssh->exec("terminal length 0");

    my $trunk_raw = eval { $ssh->exec("show interfaces trunk") } // '';
    my $vlan_raw  = eval { $ssh->exec("show vlan brief")       } // '';
    $ssh->close();

    # Parse active VLAN database entries
    my %in_db;
    $in_db{$1} = 1 while $vlan_raw =~ /^(\d+)\s+\S+\s+active/mg;

    # State-machine parse of trunk output sections
    my (%allowed, %active);
    my $mode = '';
    for my $line (split /\n/, $trunk_raw) {
        $mode = 'allowed' if $line =~ /^Port\s+Vlans allowed on trunk/;
        $mode = 'active'  if $line =~ /^Port\s+Vlans allowed and active/;
        $mode = ''        if $line =~ /^Port\s+Vlans in spanning/;
        next unless $mode && $line =~ /^(\S+)\s+([\d,\-]+)/;
        my ($port, $vlans) = ($1, $2);
        $allowed{$port} = [expand_vlans($vlans)] if $mode eq 'allowed';
        $active{$port}  = {map { $_ => 1 } expand_vlans($vlans)} if $mode eq 'active';
    }

    out("\n=== VLAN Trunk Audit: $host  [$ts] ===\n");

    unless (%allowed) {
        out("  No trunk interfaces detected on $host\n");
        return;
    }

    my ($total_prune, $total_ports) = (0, 0);
    for my $port (sort keys %allowed) {
        my @allow = @{$allowed{$port}};
        my %act   = %{$active{$port} // {}};
        my @prune = grep { !$act{$_} && $in_db{$_} } @allow;
        my @no_db = grep { !$in_db{$_} && $_ != 1  } @allow;
        my $pct   = @allow ? int(100 * keys(%act) / @allow) : 0;

        out(sprintf("  %-22s  allowed: %4d  active: %4d  util: %3d%%\n",
            $port, scalar(@allow), scalar(keys %act), $pct));

        if (@prune) {
            my $show = @prune > 10 ? join(',', @prune[0..9]) . ',...' : join(',', @prune);
            out("    [PRUNE] ${\scalar @prune} allowed but inactive: $show\n");
            $total_prune += @prune;
        }
        if (@no_db) {
            out("    [WARN]  ${\scalar @no_db} allowed but absent from VLAN DB: " . join(',', @no_db) . "\n");
        }
        $total_ports++;
    }

    out(sprintf("  Summary: %d trunk(s), %d prunable VLAN slot(s) across all trunks\n",
        $total_ports, $total_prune));
}

# --- Collect targets and run ---
my @devices;
if ($file_opt) {
    open(my $fh, '<', $file_opt) or die "Cannot open '$file_opt': $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
} elsif (@ARGV) {
    @devices  = ($ARGV[0]);
    $username = $ARGV[1] if $ARGV[1];
} else {
    die "Usage: $0 <device_ip> [username]\n" .
        "       $0 --file devices.txt [--log audit.log]\n";
}

audit_device($_) for @devices;
close $log_fh if $log_fh;