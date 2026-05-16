The target path isn't in this repo — outputting the script content directly as requested:

#!/usr/bin/perl
# =============================================================================
# cdp_lldp_neighbors.pl - CDP/LLDP Neighbor Discovery Tool
# =============================================================================
# Purpose:
#   Connects to one or more Cisco IOS/NX-OS devices via SSH and collects
#   CDP and LLDP neighbor adjacency tables. Useful for physical topology
#   documentation, change verification, and troubleshooting layer-2 adjacency
#   issues between devices.
#
# Usage:
#   Single device:  ./cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./cdp_lldp_neighbors.pl -f devices.txt -u admin -p secret -l report.txt
#   With timeout:   ./cdp_lldp_neighbors.pl -h sw01 -u admin -p secret -t 45
#
# Prerequisites:
#   Perl modules: Net::SSH::Expect, Getopt::Long (cpan Net::SSH::Expect)
#   SSH access to target devices with CDP and/or LLDP enabled
#
# Device file format (one hostname or IP per line, # for comments):
#   192.168.1.1
#   192.168.1.2
#   core-sw01.lab.local
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $pass, $device_file, $log_file, $help);
my $timeout = 30;

GetOptions(
    'host|h=s'     => \$host,
    'user|u=s'     => \$user,
    'password|p=s' => \$pass,
    'file|f=s'     => \$device_file,
    'log|l=s'      => \$log_file,
    'timeout|t=i'  => \$timeout,
    'help'         => \$help,
) or die "Argument error. Use --help for usage.\n";

if ($help || (!$host && !$device_file) || !$user || !$pass) {
    print "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-l logfile] [-t secs]\n";
    exit 1;
}

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^\s*#/;
        push @devices, $_;
    }
    close $fh;
    die "No devices found in $device_file\n" unless @devices;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>', $log_file) or die "Cannot open log $log_file: $!\n";
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
say_out($log_fh, "=" x 62);
say_out($log_fh, "CDP/LLDP Neighbor Discovery Report  $ts");
say_out($log_fh, "=" x 62);

for my $dev (@devices) {
    say_out($log_fh, "\nDevice: $dev");
    say_out($log_fh, "-" x 42);

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $dev,
            user     => $user,
            password => $pass,
            raw_pty  => 1,
            timeout  => $timeout,
        );
    };
    if ($@ || !$ssh) {
        say_out($log_fh, "  ERROR: Cannot create SSH session: $@");
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        say_out($log_fh, "  ERROR: Authentication failed");
        next;
    }

    $ssh->exec("terminal length 0");

    my $cdp = $ssh->exec("show cdp neighbors detail");
    if ($cdp && $cdp !~ /CDP is not enabled|Invalid input|% Unknown command/) {
        say_out($log_fh, "  CDP Neighbors:");
        parse_cdp($cdp, $log_fh);
    } else {
        say_out($log_fh, "  CDP: not enabled or unsupported");
    }

    my $lldp = $ssh->exec("show lldp neighbors detail");
    if ($lldp && $lldp !~ /LLDP is not enabled|Invalid input|% Unknown command/) {
        say_out($log_fh, "\n  LLDP Neighbors:");
        parse_lldp($lldp, $log_fh);
    } else {
        say_out($log_fh, "  LLDP: not enabled or unsupported");
    }

    $ssh->close();
}

close $log_fh if $log_fh;

sub parse_cdp {
    my ($output, $fh) = @_;
    my (@neighbors, %n);

    for my $line (split /\n/, $output) {
        if ($line =~ /^Device ID:\s*(.+)/) {
            push @neighbors, {%n} if $n{device_id};
            %n = (device_id => $1);
        } elsif ($line =~ /IP(?:v4)? address:\s*(\S+)/ && %n) {
            $n{ip} //= $1;
        } elsif ($line =~ /Interface:\s*(\S+),\s*Port ID[^:]*:\s*(\S+)/ && %n) {
            $n{local_intf}  = $1;
            $n{remote_intf} = $2;
        } elsif ($line =~ /Platform:\s*([^,]+)/ && %n) {
            ($n{platform} = $1) =~ s/^\s+|\s+$//g;
        }
    }
    push @neighbors, {%n} if $n{device_id};

    if (@neighbors) {
        say_out($fh, sprintf("    %-32s %-16s %-18s %-18s %s",
            "Device ID", "IP", "Local Intf", "Remote Intf", "Platform"));
        say_out($fh, "    " . "-" x 96);
        for my $r (@neighbors) {
            say_out($fh, sprintf("    %-32s %-16s %-18s %-18s %s",
                $r->{device_id}   // '-',
                $r->{ip}          // '-',
                $r->{local_intf}  // '-',
                $r->{remote_intf} // '-',
                $r->{platform}    // '-'));
        }
        say_out($fh, "    Total: " . scalar(@neighbors) . " CDP neighbor(s)");
    } else {
        say_out($fh, "    No CDP neighbors found");
    }
}

sub parse_lldp {
    my ($output, $fh) = @_;
    my (@neighbors, %n);

    for my $line (split /\n/, $output) {
        if ($line =~ /^-{3,}/) {
            push @neighbors, {%n} if $n{system_name};
            %n = ();
        } elsif ($line =~ /System Name:\s*(.+)/) {
            ($n{system_name} = $1) =~ s/^\s+|\s+$//g;
        } elsif ($line =~ /Management Addresses?:.*?(\d+\.\d+\.\d+\.\d+)/ ||
                 $line =~ /^\s+IP(?:v4)?:\s*(\d+\.\d+\.\d+\.\d+)/) {
            $n{ip} //= $1;
        } elsif ($line =~ /Local Intf:\s*(\S+)/) {
            $n{local_intf} = $1;
        } elsif ($line =~ /Port id:\s*(.+)/) {
            ($n{port_id} = $1) =~ s/^\s+|\s+$//g;
        } elsif ($line =~ /System Capabilities:\s*(.+)/) {
            ($n{capabilities} = $1) =~ s/^\s+|\s+$//g;
        }
    }
    push @neighbors, {%n} if $n{system_name};

    if (@neighbors) {
        say_out($fh, sprintf("    %-32s %-16s %-18s %-18s %s",
            "System Name", "IP", "Local Intf", "Port ID", "Capabilities"));
        say_out($fh, "    " . "-" x 96);
        for my $r (@neighbors) {
            say_out($fh, sprintf("    %-32s %-16s %-18s %-18s %s",
                $r->{system_name} // '-',
                $r->{ip}          // '-',
                $r->{local_intf}  // '-',
                $r->{port_id}     // '-',
                $r->{capabilities}// '-'));
        }
        say_out($fh, "    Total: " . scalar(@neighbors) . " LLDP neighbor(s)");
    } else {
        say_out($fh, "    No LLDP neighbors found");
    }
}

sub say_out {
    my ($fh, $msg) = @_;
    print "$msg\n";
    print $fh "$msg\n" if $fh;
}