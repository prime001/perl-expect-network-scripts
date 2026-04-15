```perl
#!/usr/bin/perl
# =============================================================================
# vlan_trunk_audit.pl - VLAN Trunk Port Pruning Verification Tool
# =============================================================================
# Purpose:
#   Audits trunk port VLAN allowed lists against active VLANs on the switch.
#   Identifies over-provisioned trunks (VLANs allowed but not active) and
#   under-provisioned trunks (active VLANs missing from allowed list).
#   Useful for enforcing trunk pruning best practices in multi-switch environments.
#
# Usage:
#   ./vlan_trunk_audit.pl -h <host> -u <user> -p <pass> [-l <logfile>]
#   ./vlan_trunk_audit.pl -f <device_list.txt> -u <user> -p <pass> [-l <logfile>]
#
# Prerequisites:
#   CPAN: Net::SSH::Expect, Getopt::Long
#   SSH access to Cisco IOS/IOS-XE switches
#   User account with privilege 15 or 'show' rights
#
# Output:
#   Per-trunk: allowed VLANs, active VLANs, over-provisioned, under-provisioned
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $logfile);
GetOptions(
    'h=s' => \$host,
    'f=s' => \$file,
    'u=s' => \$user,
    'p=s' => \$pass,
    'l=s' => \$logfile,
) or die "Usage: $0 -h <host>|-f <file> -u <user> -p <pass> [-l <logfile>]\n";

die "Provide -h <host> or -f <file>\n" unless $host || $file;
die "Username (-u) required\n" unless $user;
die "Password (-p) required\n" unless $pass;

my @hosts = $host ? ($host) : do {
    open my $fh, '<', $file or die "Cannot open $file: $!";
    map { chomp; $_ } grep { /\S/ && !/^#/ } <$fh>;
};

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open logfile $logfile: $!";
}

sub log_out {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub expand_vlan_range {
    my ($range_str) = @_;
    my %vlans;
    for my $token (split /,/, $range_str) {
        $token =~ s/\s//g;
        if ($token =~ /^(\d+)-(\d+)$/) {
            $vlans{$_}++ for $1..$2;
        } elsif ($token =~ /^\d+$/) {
            $vlans{$token}++;
        }
    }
    return %vlans;
}

sub audit_device {
    my ($device) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    log_out("\n[$ts] Connecting to $device...\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password     => $pass,
        raw_pty      => 1,
        timeout      => 15,
        ssh_option   => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        log_out("  ERROR: Cannot connect to $device - $@\n");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$', 5);

    # Get active VLANs from vlan brief
    $ssh->send("show vlan brief");
    my $vlan_brief = $ssh->waitfor('\$', 20) // '';
    my %active_vlans;
    while ($vlan_brief =~ /^(\d+)\s+\S+\s+active/mg) {
        $active_vlans{$1}++;
    }

    # Get trunk interface details
    $ssh->send("show interfaces trunk");
    my $trunk_output = $ssh->waitfor('\$', 20) // '';
    $ssh->send("exit");

    if (!$trunk_output || $trunk_output !~ /Port\s+Mode/i) {
        log_out("  WARNING: No trunk output or unsupported format on $device\n");
        return;
    }

    # Parse trunk sections: extract allowed and active per port
    my (%trunk_allowed, %trunk_forwarding);
    my $section = '';
    for my $line (split /\n/, $trunk_output) {
        $section = 'allowed'     if $line =~ /VLANs allowed on trunk/i;
        $section = 'forwarding'  if $line =~ /VLANs in spanning tree forwarding/i;
        $section = ''            if $line =~ /^Port\s+Vlans\s+in\s+STP/i && $section eq 'allowed';

        if ($section eq 'allowed' && $line =~ /^((?:Gi|Fa|Te|Hu|Et)\S+)\s+([\d,\-]+)/i) {
            $trunk_allowed{$1} = $2;
        }
        if ($section eq 'forwarding' && $line =~ /^((?:Gi|Fa|Te|Hu|Et)\S+)\s+([\d,\-]+)/i) {
            $trunk_forwarding{$1} = $2;
        }
    }

    log_out(sprintf("  %-20s  %-10s  %-10s  %s\n", "Interface", "Allowed", "Forwarding", "Issues"));
    log_out("  " . "-" x 70 . "\n");

    for my $port (sort keys %trunk_allowed) {
        my %allowed    = expand_vlan_range($trunk_allowed{$port} // '');
        my %forwarding = expand_vlan_range($trunk_forwarding{$port} // '');

        my @over  = sort { $a <=> $b } grep { !$active_vlans{$_} } keys %allowed;
        my @under = sort { $a <=> $b } grep { $allowed{$_} && !$forwarding{$_} } keys %active_vlans;

        my @issues;
        push @issues, "OVER-PROVISIONED(" . join(',', @over) . ")"   if @over  && scalar(@over)  < 20;
        push @issues, "OVER-PROVISIONED(" . scalar(@over) . " VLANs)" if @over && scalar(@over) >= 20;
        push @issues, "MISSING-ACTIVE("   . join(',', @under) . ")"  if @under && scalar(@under) < 20;
        push @issues, "MISSING-ACTIVE("   . scalar(@under) . " VLANs)" if @under && scalar(@under) >= 20;

        my $issue_str = @issues ? join('; ', @issues) : 'OK';
        log_out(sprintf("  %-20s  %-10d  %-10d  %s\n",
            $port,
            scalar(keys %allowed),
            scalar(keys %forwarding),
            $issue_str));
    }

    log_out("  Active VLANs on switch: " . join(', ', sort { $a <=> $b } keys %active_vlans) . "\n");
}

log_out("=" x 72 . "\n");
log_out("VLAN Trunk Pruning Audit - " . strftime("%Y-%m-%d %H:%M:%S", localtime) . "\n");
log_out("=" x 72 . "\n");

audit_device($_) for @hosts;

log_out("\nAudit complete.\n");
close $log_fh if $log_fh;
```