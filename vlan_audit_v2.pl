No specific skills apply to this code generation task. Writing the Perl trunk VLAN audit script now.

#!/usr/bin/perl
#
# vlan_trunk_audit.pl - Cisco VLAN Trunk Pruning and Consistency Audit
#
# PURPOSE:
#   Audits trunk interfaces for VLAN inconsistencies on Cisco IOS devices.
#   Cross-references allowed, active, and STP-forwarding VLAN sets to surface:
#     - Ghost VLANs: allowed on trunk but absent from the VLAN database
#     - Stranded VLANs: in the VLAN database but pruned from every trunk
#     - Blocked ports: trunks with no VLANs in STP forwarding state
#   Complements vlan_audit.pl (database listing) and vlan_audit_v2.pl (detail
#   report) by focusing on trunk-layer pruning and cross-device consistency.
#
# USAGE:
#   Single device:  perl vlan_trunk_audit.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    perl vlan_trunk_audit.pl -f devices.txt -u admin -p secret
#   With log file:  perl vlan_trunk_audit.pl -h 192.168.1.1 -u admin -p secret -l audit.log
#   Custom timeout: perl vlan_trunk_audit.pl -h 192.168.1.1 -u admin -p secret -t 45
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   SSH enabled on target device (crypto key generate rsa; ip ssh version 2)
#   Account requires at minimum privilege 1 (show commands only)
#
# DEVICE FILE FORMAT (one entry per line; inline # comments ignored):
#   192.168.1.1
#   sw-core-01.example.com   # aggregation layer
#
# EXIT CODES:
#   0 = clean audit (no issues found on any device)
#   1 = issues found or connection errors
#

use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case);
use Net::SSH::Expect;
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log, $opt_timeout);
$opt_timeout = 30;

GetOptions(
    'h|host=s'    => \$opt_host,
    'f|file=s'    => \$opt_file,
    'u|user=s'    => \$opt_user,
    'p|pass=s'    => \$opt_pass,
    'l|log=s'     => \$opt_log,
    't|timeout=i' => \$opt_timeout,
) or die "Usage: $0 -h host|-f file -u user -p pass [-l logfile] [-t timeout]\n";

die "Specify -h host or -f file\n"  unless $opt_host || $opt_file;
die "Username required (-u)\n"      unless $opt_user;
die "Password required (-p)\n"      unless $opt_pass;

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open my $fh, '<', $opt_file or die "Cannot open $opt_file: $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        push @devices, $_ if length $_;
    }
    close $fh;
}
die "No devices to process\n" unless @devices;

my $log_fh;
if ($opt_log) {
    open $log_fh, '>', $opt_log or die "Cannot open $opt_log: $!\n";
}

my $issues_found = 0;

sub say_out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub expand_range {
    my ($str) = @_;
    my @out;
    for my $tok (split /,/, $str // '') {
        if ($tok =~ /^(\d+)-(\d+)$/) { push @out, ($1..$2) }
        elsif ($tok =~ /^\d+$/)      { push @out, $tok }
    }
    return @out;
}

sub audit_device {
    my ($dev) = @_;
    say_out("\n" . "=" x 62 . "\n");
    say_out(sprintf "Device : %s\n", $dev);
    say_out(sprintf "Time   : %s\n", strftime("%Y-%m-%d %H:%M:%S", localtime));
    say_out("=" x 62 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $dev,
        user     => $opt_user,
        password => $opt_pass,
        raw_pty  => 1,
        timeout  => $opt_timeout,
    );

    eval {
        my $banner = $ssh->login();
        die "unexpected prompt after login\n" unless $banner =~ /[>#]/;
    };
    if ($@) {
        chomp(my $err = $@);
        say_out("  ERROR: Cannot connect - $err\n");
        $issues_found = 1;
        return;
    }

    $ssh->exec("terminal length 0");

    my $vlan_raw  = $ssh->exec("show vlan brief");
    my $trunk_raw = $ssh->exec("show interfaces trunk");
    $ssh->close();

    # Parse VLAN database
    my %vlan_db;
    for (split /\n/, $vlan_raw) {
        $vlan_db{$1} = $2 if /^(\d+)\s+(\S+)\s+active/;
    }

    # Parse trunk sections
    my (%allowed, %active, %forwarding, @iface_order);
    my ($section, $iface) = ('', '');
    for (split /\n/, $trunk_raw) {
        if    (/^Port\s+Mode\s+Encapsulation/i)                          { $section = 'hdr' }
        elsif (/^Port\s+Vlans allowed on trunk/i)                        { $section = 'allowed' }
        elsif (/^Port\s+Vlans allowed and active/i)                      { $section = 'active' }
        elsif (/^Port\s+Vlans in spanning tree forwarding/i)             { $section = 'fwd' }
        elsif ($section eq 'hdr'     && /^(\S+)\s+\S+\s+\S+/)           { $iface = $1; push @iface_order, $iface; $allowed{$iface} = []; $forwarding{$iface} = [] }
        elsif ($section eq 'allowed' && /^(\S+)\s+([\d,\-]+)/)          { $allowed{$1}     = [expand_range($2)] }
        elsif ($section eq 'active'  && /^(\S+)\s+([\d,\-]+)/)          { $active{$1}      = [expand_range($2)] }
        elsif ($section eq 'fwd'     && /^(\S+)\s+([\d,\-]+)/)          { $forwarding{$1}  = [expand_range($2)] }
    }

    unless (@iface_order) {
        say_out("  No trunk interfaces found\n");
        return;
    }

    my %carried_on_any;
    my $device_clean = 1;

    for my $intf (@iface_order) {
        my @alw = @{ $allowed{$intf}    // [] };
        my @fwd = @{ $forwarding{$intf} // [] };
        my %fwd_set = map { $_ => 1 } @fwd;
        $carried_on_any{$_}++ for @alw;

        my @ghosts  = grep { !exists $vlan_db{$_} } @alw;
        my @pruned  = grep { !$fwd_set{$_} && exists $vlan_db{$_} && $_ != 1 } @alw;
        my $blocked = (@alw && !@fwd) ? 1 : 0;

        say_out(sprintf "\n  %-28s  allowed=%-4d  forwarding=%-4d\n",
                $intf, scalar @alw, scalar @fwd);

        if (@ghosts) {
            say_out("    [WARN] Ghost VLANs (allowed, not in DB): "
                    . join(',', sort { $a<=>$b } @ghosts) . "\n");
            $issues_found = $device_clean = 1;
        }
        if ($blocked) {
            say_out("    [WARN] Trunk has no VLANs in STP forwarding state\n");
            $issues_found = $device_clean = 1;
        }
        if (@pruned > 20) {
            say_out(sprintf "    [INFO] %d VLANs pruned/blocked by STP\n", scalar @pruned);
        } elsif (@pruned) {
            say_out("    [INFO] Pruned/STP-blocked: " . join(',', sort { $a<=>$b } @pruned) . "\n");
        }
    }

    # Stranded: in DB but not allowed on any trunk (skip VLAN 1)
    my @stranded = sort { $a<=>$b }
                   grep { $_ > 1 && !$carried_on_any{$_} }
                   keys %vlan_db;

    say_out(sprintf "\n  DB VLANs: %d   Trunks: %d\n",
            scalar keys %vlan_db, scalar @iface_order);
    if (@stranded) {
        say_out("  [WARN] Stranded VLANs (in DB, not on any trunk): "
                . join(',', @stranded) . "\n");
        $issues_found = 1;
    } else {
        say_out("  [OK]   No stranded VLANs\n");
    }
    say_out($device_clean ? "  [OK]   No per-trunk issues\n" : "");
}

say_out("VLAN Trunk Pruning Audit\n");
say_out("Generated: " . strftime("%Y-%m-%d %H:%M:%S", localtime) . "\n");

audit_device($_) for @devices;

say_out("\nAudit complete. " . scalar(@devices) . " device(s) processed.\n");
close $log_fh if $log_fh;
exit $issues_found;