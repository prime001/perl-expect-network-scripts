```perl
#!/usr/bin/perl
# =============================================================================
# vlan_orphan_check.pl - Orphaned VLAN and Trunk Mismatch Detector
# =============================================================================
# Purpose : Identifies VLANs defined in the database but not active on any
#           access or trunk port, and trunk ports missing expected VLANs.
#           Complements vlan_audit.pl (basic inventory) and vlan_audit_v2.pl
#           (extended stats) with consistency/hygiene analysis.
#
# Usage   : perl vlan_orphan_check.pl -h <host> [-u <user>] [-p <pass>]
#                                     [-f <device_file>] [-o <logfile>]
#           Device file: one IP or hostname per line, comments (#) ignored.
#
# Output  : Per-device report: orphaned VLANs, access-only VLANs, trunk gaps.
#
# Prereqs : Net::SSH::Expect  (cpanm Net::SSH::Expect)
#           Tested against Cisco IOS / IOS-XE; adapt regexes for NX-OS/EOS.
# =============================================================================

use strict;
use warnings;
use Getopt::Long;
use Net::SSH::Expect;

my ($host, $user, $pass, $device_file, $logfile);
$user = $ENV{NET_USER} // 'admin';
$pass = $ENV{NET_PASS} // '';

GetOptions(
    'h|host=s'   => \$host,
    'u|user=s'   => \$user,
    'p|pass=s'   => \$pass,
    'f|file=s'   => \$device_file,
    'o|log=s'    => \$logfile,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-o logfile]\n";

die "Provide -h <host> or -f <file>\n" unless $host || $device_file;

my @devices;
push @devices, $host if $host;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if length }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>', $logfile or die "Cannot open $logfile: $!";
}

sub emit {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my ($dev) = @_;
    emit("\n=== $dev ===\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $dev,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => 20,
    );

    eval {
        my $login = $ssh->login();
        die "Auth failed" unless $login =~ /[>#]/;
    };
    if ($@) {
        emit("  [ERROR] Connection/auth failed: $@\n");
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('[>#]', 10);

    # Collect VLAN database
    $ssh->send("show vlan brief\n");
    my $vlan_brief = $ssh->waitfor('[>#]', 15) // '';

    # Collect trunk status
    $ssh->send("show interfaces trunk\n");
    my $trunk_out = $ssh->waitfor('[>#]', 15) // '';

    $ssh->send("exit\n");
    $ssh->close();

    # Parse VLANs from database (skip 1 and reserved 1002-1005)
    my %vlan_db;
    for my $line (split /\n/, $vlan_brief) {
        if ($line =~ /^(\d+)\s+(\S+)\s+(active|act\/lshut)\s+(.*)/) {
            my ($id, $name, $state, $ports) = ($1, $2, $3, $4);
            next if $id == 1 || ($id >= 1002 && $id <= 1005);
            my @port_list = grep { length } split /[\s,]+/, $ports;
            $vlan_db{$id} = { name => $name, ports => \@port_list };
        }
    }

    if (!%vlan_db) {
        emit("  No user VLANs found (or parse failed).\n");
        return;
    }

    # Parse trunk allowed VLANs
    my %trunked_vlans;
    my $in_allowed = 0;
    for my $line (split /\n/, $trunk_out) {
        $in_allowed = 1 if $line =~ /VLANs allowed and active in management domain/;
        if ($in_allowed && $line =~ /^\S+\s+([\d,\-]+)/) {
            for my $part (split /,/, $1) {
                if ($part =~ /(\d+)-(\d+)/) { $trunked_vlans{$_}++ for $1..$2 }
                elsif ($part =~ /(\d+)/)    { $trunked_vlans{$1}++ }
            }
        }
    }

    # Classify
    my (@orphaned, @access_only, @trunked_not_db);
    for my $id (sort { $a <=> $b } keys %vlan_db) {
        my $has_access = @{ $vlan_db{$id}{ports} } > 0;
        my $has_trunk  = exists $trunked_vlans{$id};
        push @orphaned,    $id unless $has_access || $has_trunk;
        push @access_only, $id if $has_access && !$has_trunk;
    }
    for my $id (sort { $a <=> $b } keys %trunked_vlans) {
        push @trunked_not_db, $id unless exists $vlan_db{$id} || $id == 1;
    }

    my $total = scalar keys %vlan_db;
    emit(sprintf "  DB VLANs: %d  |  Orphaned: %d  |  Access-only: %d  |  Trunk-not-in-DB: %d\n",
        $total, scalar @orphaned, scalar @access_only, scalar @trunked_not_db);

    if (@orphaned) {
        emit("  [WARN] Orphaned (no ports, not trunked): " . join(', ', @orphaned) . "\n");
        for my $id (@orphaned) {
            emit(sprintf "         VLAN %-5d  %s\n", $id, $vlan_db{$id}{name});
        }
    }
    if (@trunked_not_db) {
        emit("  [WARN] Trunked VLANs not in local DB (pruned or missing): "
            . join(', ', @trunked_not_db) . "\n");
    }
    unless (@orphaned || @trunked_not_db) {
        emit("  [OK] No orphaned VLANs or trunk inconsistencies detected.\n");
    }
}

my $ts = localtime;
emit("VLAN Orphan/Consistency Check  $ts\n");
emit("Devices: " . scalar(@devices) . "\n");

audit_device($_) for @devices;

emit("\nDone.\n");
close $log_fh if $log_fh;
```