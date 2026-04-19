#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# vlan_stp_audit.pl - VLAN Spanning Tree Protocol Audit Tool
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches and audits STP (Spanning Tree
#   Protocol) state per VLAN. Reports root bridge identity, port roles/states,
#   topology change counts, and flags VLANs with active TCN activity or
#   suboptimal root placement.
#
# Usage:
#   ./vlan_stp_audit.pl -h <host> -u <user> -p <pass> [-l <logfile>]
#   ./vlan_stp_audit.pl -f <device_list.txt> -u <user> -p <pass> [-l <logfile>]
#
# Prerequisites:
#   - Net::SSH::Expect (cpan install Net::SSH::Expect)
#   - SSH enabled on target device with valid credentials
#   - 'terminal length 0' supported (standard IOS)
#   - Read-only or higher privilege level
#
# Output:
#   Per-VLAN STP summary including root bridge, hello/max/fwd timers,
#   topology change count, and ports in non-forwarding states.
# =============================================================================

my ($host, $user, $pass, $device_file, $logfile);
my $timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'f|file=s'     => \$device_file,
    'l|log=s'      => \$logfile,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l <logfile>] [-t <timeout>]\n";

die "Must specify -u <user> and -p <pass>\n" unless $user && $pass;
die "Must specify -h <host> or -f <file>\n"  unless $host || $device_file;

my @devices;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        s/#.*//;
        s/^\s+|\s+$//g;
        push @devices, $_ if length($_);
    }
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open logfile $logfile: $!\n";
}

sub log_print {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my $device = shift;
    my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);

    log_print("=" x 70 . "\n");
    log_print("Host: $device  |  Time: $timestamp\n");
    log_print("=" x 70 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        log_print("ERROR: SSH login failed for $device: $@\n\n");
        return;
    }
    if ($login_output =~ /Permission denied|Authentication failed/i) {
        log_print("ERROR: Authentication failed for $device\n\n");
        $ssh->close();
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|#|\>', 5);

    $ssh->send("show spanning-tree\n");
    my $stp_output = '';
    eval {
        $ssh->waitfor('\$|#|\>', $timeout);
        $stp_output = $ssh->before();
    };
    if ($@ || !$stp_output) {
        log_print("ERROR: No response to 'show spanning-tree' on $device\n\n");
        $ssh->close();
        return;
    }

    $ssh->send("show spanning-tree summary totals\n");
    my $summary_output = '';
    eval {
        $ssh->waitfor('\$|#|\>', 10);
        $summary_output = $ssh->before();
    };

    $ssh->send("exit\n");
    $ssh->close();

    parse_and_report($device, $stp_output, $summary_output);
}

sub parse_and_report {
    my ($device, $stp_out, $summary_out) = @_;

    my %vlans;
    my $current_vlan;

    for my $line (split /\n/, $stp_out) {
        if ($line =~ /^VLAN(\d+)\s+(\S+)/) {
            $current_vlan = $1;
            $vlans{$current_vlan}{mode} = $2;
        }
        next unless $current_vlan;

        if ($line =~ /Root ID.*Priority\s+(\d+)/) {
            $vlans{$current_vlan}{root_priority} = $1;
        }
        if ($line =~ /Address\s+([0-9a-fA-F.]+)/ && !exists $vlans{$current_vlan}{root_mac}) {
            $vlans{$current_vlan}{root_mac} = $1;
        }
        if ($line =~ /This bridge is the root/i) {
            $vlans{$current_vlan}{is_root} = 1;
        }
        if ($line =~ /Topology change count\s+(\d+)/i) {
            $vlans{$current_vlan}{tc_count} = $1;
        }
        if ($line =~ /Times:\s+Hello\s+([\d.]+),\s+Max Age\s+([\d.]+),\s+Forward Delay\s+([\d.]+)/i) {
            $vlans{$current_vlan}{hello}   = $1;
            $vlans{$current_vlan}{maxage}  = $2;
            $vlans{$current_vlan}{fwddly}  = $3;
        }
        if ($line =~ /^\s+(\S+)\s+(Root|Desg|Altn|Back|Mast)\s+(FWD|BLK|LIS|LRN|DIS)\s+/i) {
            my ($port, $role, $state) = ($1, $2, $3);
            push @{$vlans{$current_vlan}{ports}}, { port => $port, role => $role, state => $state };
        }
    }

    if (!%vlans) {
        log_print("  No STP data parsed from $device (check output format)\n\n");
        return;
    }

    my $total_vlans    = scalar keys %vlans;
    my $root_vlans     = grep { $_->{is_root} } values %vlans;
    my $blocking_vlans = 0;
    my $tc_warn_vlans  = 0;

    log_print(sprintf("  %-10s %-8s %-20s %-5s %-5s %-5s  %-5s  %s\n",
        'VLAN', 'Mode', 'Root MAC', 'Pri', 'Helo', 'FwdD', 'TCN', 'Flags'));
    log_print("  " . "-" x 68 . "\n");

    for my $vid (sort { $a <=> $b } keys %vlans) {
        my $v    = $vlans{$vid};
        my $flags = '';
        $flags .= '[ROOT] '    if $v->{is_root};
        $flags .= '[HIGH-TCN] ' if ($v->{tc_count} // 0) > 100;
        $flags .= '[BLK-PORTS] ' if grep { $_->{state} eq 'BLK' } @{$v->{ports} // []};

        $blocking_vlans++ if grep { $_->{state} eq 'BLK' } @{$v->{ports} // []};
        $tc_warn_vlans++  if ($v->{tc_count} // 0) > 100;

        log_print(sprintf("  VLAN%-6s %-8s %-20s %-5s %-5s %-5s  %-5s  %s\n",
            $vid,
            $v->{mode}         // 'unknown',
            $v->{root_mac}     // 'n/a',
            $v->{root_priority} // '-',
            $v->{hello}        // '-',
            $v->{fwddly}       // '-',
            $v->{tc_count}     // '0',
            $flags));
    }

    log_print("\n  Summary: $total_vlans VLANs | Root here: $root_vlans | " .
              "VLANs w/ blocking ports: $blocking_vlans | High TCN: $tc_warn_vlans\n");

    if ($summary_out =~ /(\d+)\s+vlans.*?(\d+)\s+in.*?forwarding/si) {
        log_print("  STP totals from summary: $1 VLANs active\n");
    }

    log_print("\n");
}

for my $dev (@devices) {
    audit_device($dev);
}

close($log_fh) if $log_fh;