#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# cdp_lldp_neighbors.pl - CDP/LLDP Neighbor Discovery Collector
# =============================================================================
# Purpose:
#   Connects to Cisco IOS/IOS-XE/NX-OS devices via SSH and collects CDP and
#   LLDP neighbor detail output. Useful for automated topology discovery,
#   asset audits, and verifying physical cabling against intended design.
#
# Usage:
#   ./cdp_lldp_neighbors.pl --host <ip> [--user <username>] [--pass <password>]
#   ./cdp_lldp_neighbors.pl --file devices.txt [--user <username>] [--pass <password>]
#   ./cdp_lldp_neighbors.pl --host 10.0.0.1 --user admin --pass secret --log neighbors.log
#
# Prerequisites:
#   - Net::SSH::Expect (cpan install Net::SSH::Expect)
#   - CDP and/or LLDP enabled on target devices
#   - SSH access with privilege level sufficient to run show commands
#
# Output:
#   Neighbor entries including device ID, IP, platform, interface, and
#   capabilities — printed to STDOUT and optionally written to a log file.
# =============================================================================

my ($host, $file, $username, $password, $logfile, $timeout);
$username = $ENV{NET_USER} // 'admin';
$password = $ENV{NET_PASS} // '';
$timeout  = 30;

GetOptions(
    'host=s'    => \$host,
    'file=s'    => \$file,
    'user=s'    => \$username,
    'pass=s'    => \$password,
    'log=s'     => \$logfile,
    'timeout=i' => \$timeout,
) or die "Usage: $0 --host <ip>|--file <list> [--user u] [--pass p] [--log file]\n";

die "ERROR: Specify --host or --file\n" unless $host || $file;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $file) or die "Cannot open device list '$file': $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^#/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log '$logfile': $!\n";
}

sub output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub collect_neighbors {
    my ($device) = @_;
    my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);

    output("=" x 70 . "\n");
    output("Device: $device  |  Collected: $timestamp\n");
    output("=" x 70 . "\n");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host        => $device,
            user        => $username,
            password     => $password,
            raw_pty     => 1,
            timeout     => $timeout,
            ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
        $ssh->login();
    };
    if ($@ || !$ssh) {
        output("  ERROR: SSH connection failed to $device: $@\n\n");
        return;
    }

    # Disable paging
    eval { $ssh->exec('terminal length 0'); };

    my @commands = (
        'show cdp neighbors detail',
        'show lldp neighbors detail',
    );

    for my $cmd (@commands) {
        output("\n--- $cmd ---\n");
        my $output = eval { $ssh->exec($cmd) };
        if ($@) {
            output("  TIMEOUT or error running '$cmd': $@\n");
            next;
        }

        # Strip the echoed command and prompt lines
        $output =~ s/^\Q$cmd\E\r?\n//;
        $output =~ s/\r//g;

        # Check for unsupported protocol
        if ($output =~ /Invalid input|% CDP is not enabled|% LLDP is not enabled|not enabled/i) {
            output("  (Protocol not enabled or not supported on this device)\n");
            next;
        }

        # Parse and summarize neighbor entries
        my @neighbors;
        my %entry;

        for my $line (split /\n/, $output) {
            if ($line =~ /^Device ID:\s*(.+)/i || $line =~ /^System Name:\s*(.+)/i) {
                if (%entry) { push @neighbors, {%entry}; %entry = (); }
                $entry{device_id} = $1;
            }
            elsif ($line =~ /IP[Vv]?(?:4)? [Aa]ddress(?:es)?:\s*(.+)/i || $line =~ /Management [Aa]ddress.*?:\s*([\d\.]+)/i) {
                $entry{ip} //= $1;
            }
            elsif ($line =~ /Platform:\s*([^,]+)/i) {
                ($entry{platform} = $1) =~ s/^\s+|\s+$//g;
            }
            elsif ($line =~ /Interface:\s*(\S+)/i || $line =~ /Local intf[a-z]*:\s*(\S+)/i) {
                $entry{local_intf} //= $1;
            }
            elsif ($line =~ /Port ID.*?:\s*(\S+)/i) {
                $entry{remote_intf} //= $1;
            }
            elsif ($line =~ /Capabilities:\s*(.+)/i) {
                $entry{capabilities} = $1;
            }
        }
        push @neighbors, {%entry} if %entry;

        if (@neighbors) {
            output(sprintf("  %-30s %-16s %-12s %-16s %s\n",
                'Neighbor', 'IP', 'Local Intf', 'Remote Intf', 'Platform'));
            output("  " . "-" x 90 . "\n");
            for my $n (@neighbors) {
                output(sprintf("  %-30s %-16s %-12s %-16s %s\n",
                    $n->{device_id}   // '(unknown)',
                    $n->{ip}          // 'N/A',
                    $n->{local_intf}  // 'N/A',
                    $n->{remote_intf} // 'N/A',
                    $n->{platform}    // '',
                ));
            }
            output("  Total neighbors: " . scalar(@neighbors) . "\n");
        } else {
            output("  No neighbors found.\n");
        }
    }

    eval { $ssh->close(); };
    output("\n");
}

collect_neighbors($_) for @devices;

close $log_fh if $log_fh;