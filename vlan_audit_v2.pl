This is a standalone script generation request — writing directly to STDOUT as instructed.

#!/usr/bin/perl
#
# vlan_trunk_audit.pl - VLAN Trunk Pruning and Consistency Auditor
#
# Purpose:
#   Audits trunk port configurations against the local VLAN database on
#   Cisco IOS/IOS-XE switches. Identifies orphaned VLANs (allowed on
#   trunks but absent from the VLAN DB), flags misconfigured native VLANs,
#   and reports VLANs defined locally but not propagated on any trunk.
#   Useful for catching stale trunk configs after VLAN cleanup or merges.
#
# Usage:
#   ./vlan_trunk_audit.pl -h <host> -u <user> -p <pass> [-l <logfile>]
#   ./vlan_trunk_audit.pl -f <device_file> -u <user> -p <pass> [-l <logfile>]
#
# Device file: one IP or hostname per line; lines starting with # are ignored.
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#   SSH must be enabled on target devices with password authentication.
#   Tested on Cisco IOS 15.x and IOS-XE 16.x/17.x.
#
# Exit codes: 0 = clean, 1 = issues found, 2 = all connections failed
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $pass, $device_file, $logfile);
my $timeout = 15;

GetOptions(
    'h|host=s'     => \$host,
    'u|user=s'     => \$user,
    'p|password=s' => \$pass,
    'f|file=s'     => \$device_file,
    'l|log=s'      => \$logfile,
    't|timeout=i'  => \$timeout,
) or usage();

usage() unless ($host || $device_file) && $user && $pass;

my @devices = $host ? ($host) : read_device_file($device_file);
die "No devices to process\n" unless @devices;

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log $logfile: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=" x 62, $log_fh);
out("VLAN Trunk Consistency Audit  $ts", $log_fh);
out("=" x 62, $log_fh);

my ($issues, $conn_errors) = (0, 0);
for my $dev (@devices) {
    my $rc = audit_device($dev, $user, $pass, $timeout, $log_fh);
    $issues++      if $rc == 1;
    $conn_errors++ if $rc == 2;
}

out("=" x 62, $log_fh);
out(sprintf("Done. %d device(s) with issues, %d connection error(s).",
    $issues, $conn_errors), $log_fh);

close($log_fh) if $log_fh;
exit($issues ? 1 : ($conn_errors == @devices ? 2 : 0));

# ------------------------------------------------------------------

sub audit_device {
    my ($device, $user, $pass, $timeout, $log_fh) = @_;

    out("\n[*] $device", $log_fh);

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $user,
        password => $pass,
        raw_pty  => 1,
        timeout  => $timeout,
    );

    my $banner;
    eval { $banner = $ssh->login() };
    if ($@ || !defined $banner || $banner =~ /denied|fail|incorrect/i) {
        out("    [ERROR] Connection or auth failed: " . ($@ // 'bad credentials'), $log_fh);
        return 2;
    }

    $ssh->exec("terminal length 0");

    my $ver = $ssh->exec("show version | include uptime");
    my $hostname = ($ver =~ /^(\S+)\s+uptime/) ? $1 : $device;
    out("    Host   : $hostname", $log_fh);

    # Build VLAN database (skip extended range 1006-4094 unless present)
    my %vlan_db;
    for my $line (split /\n/, $ssh->exec("show vlan brief")) {
        $vlan_db{$1} = $2 if $line =~ /^(\d+)\s+(\S+)\s+active/i;
    }
    out("    VLAN DB: " . scalar(keys %vlan_db) . " active VLANs", $log_fh);

    # Parse trunk table in three passes (mode/native, allowed, active)
    my (%native, %allowed, %active);
    my ($section, $port) = ('', '');

    for my $line (split /\n/, $ssh->exec("show interfaces trunk")) {
        if    ($line =~ /^Port\s+Vlans allowed on trunk/i)     { $section = 'allowed' }
        elsif ($line =~ /^Port\s+Vlans allowed and active/i)   { $section = 'active'  }
        elsif ($line =~ /^Port\s+/i)                           { $section = 'mode'    }

        if ($section eq 'mode' &&
            $line =~ /^((?:Gi|Fa|Te|Hu|Po|Eth)\S+)\s+\S+\s+\S+\s+\S+\s+(\d+)/) {
            ($port, $native{$1}) = ($1, $2);
        }
        elsif ($section eq 'allowed' &&
               $line =~ /^((?:Gi|Fa|Te|Hu|Po|Eth)\S+)\s+([\d,\-]+)/) {
            $allowed{$1} = expand_range($2);
        }
        elsif ($section eq 'active' &&
               $line =~ /^((?:Gi|Fa|Te|Hu|Po|Eth)\S+)\s+([\d,\-]+)/) {
            $active{$1} = expand_range($2);
        }
    }

    unless (keys %allowed) {
        out("    [INFO]  No trunk ports found", $log_fh);
        $ssh->close();
        return 0;
    }
    out("    Trunks : " . scalar(keys %allowed) . " trunk port(s)", $log_fh);

    my $dev_issues = 0;
    my %all_trunked;

    for my $iface (sort keys %allowed) {
        my @iface_allowed = @{ $allowed{$iface} };
        my %act_set       = map { $_ => 1 } @{ $active{$iface} // [] };
        my $nat           = $native{$iface} // '?';

        $all_trunked{$_}++ for @iface_allowed;

        my @orphan  = grep { !exists $vlan_db{$_} && $_ != 1 } @iface_allowed;
        my @pruned  = grep { !$act_set{$_} }                    @iface_allowed;
        my $bad_nat = ($nat ne '1' && $nat ne '?' && !exists $vlan_db{$nat});

        if (@orphan) {
            my $show = join(',', @orphan[0 .. ($#orphan > 9 ? 9 : $#orphan)]);
            $show .= '...' if @orphan > 10;
            out("    [WARN]  $iface: " . scalar(@orphan) . " orphaned VLAN(s) (allowed, not in DB): $show", $log_fh);
            $dev_issues++;
        }
        if ($bad_nat) {
            out("    [WARN]  $iface: native VLAN $nat not in VLAN database", $log_fh);
            $dev_issues++;
        }
        unless (@orphan || $bad_nat) {
            my $pruned_str = @pruned ? ", " . scalar(@pruned) . " pruned" : "";
            out(sprintf("    [OK]    %-22s native=%-4s allowed=%-4d active=%-4d%s",
                $iface, $nat, scalar(@iface_allowed), scalar(keys %act_set), $pruned_str),
                $log_fh);
        }
    }

    # VLANs in DB but not present on any trunk (access-only or unused)
    my @local_only = grep { !$all_trunked{$_} && $_ ne '1' }
                     sort { $a <=> $b } keys %vlan_db;
    if (@local_only) {
        my $show = join(',', @local_only[0 .. ($#local_only > 14 ? 14 : $#local_only)]);
        $show .= '...' if @local_only > 15;
        out("    [INFO]  " . scalar(@local_only) . " VLAN(s) in DB but not on any trunk: $show", $log_fh);
    }

    $ssh->close();
    return $dev_issues ? 1 : 0;
}

sub expand_range {
    my ($str) = @_;
    my @out;
    for my $tok (split /,/, $str) {
        push @out, ($1 .. $2) if $tok =~ /^(\d+)-(\d+)$/;
        push @out,  $1        if $tok =~ /^(\d+)$/;
    }
    return \@out;
}

sub read_device_file {
    my ($file) = @_;
    open(my $fh, '<', $file) or die "Cannot open $file: $!\n";
    my @devs = grep { /\S/ && !/^\s*#/ } map { chomp; s/\s+//g; $_ } <$fh>;
    close $fh;
    return @devs;
}

sub out {
    my ($msg, $fh) = @_;
    print "$msg\n";
    print $fh "$msg\n" if $fh;
}

sub usage {
    die <<'END';
Usage:
  vlan_trunk_audit.pl -h <host>        -u <user> -p <pass> [-l <log>] [-t <sec>]
  vlan_trunk_audit.pl -f <device_file> -u <user> -p <pass> [-l <log>] [-t <sec>]

  -h  Single device IP or hostname
  -f  File with one device per line (# = comment)
  -u  SSH username
  -p  SSH password
  -l  Append results to log file
  -t  SSH timeout seconds (default 15)
END
}