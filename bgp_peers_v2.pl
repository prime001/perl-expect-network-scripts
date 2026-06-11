```perl
#!/usr/bin/perl
#
# bgp_advertised_routes.pl - BGP Advertised Route Verification Tool
#
# Purpose:
#   Connects to a Cisco IOS/IOS-XE router and inspects routes being advertised
#   to a specified BGP peer. Useful for validating route policies, detecting
#   potential route leaks, and verifying prefix advertisements post-change.
#
# Usage:
#   bgp_advertised_routes.pl -h <router> -p <peer-ip> [-u <user>] [-l <logfile>]
#   bgp_advertised_routes.pl -f <device-file> -p <peer-ip> [-u <user>] [-l <logfile>]
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH key auth recommended; script prompts for password if needed
#
# Examples:
#   bgp_advertised_routes.pl -h 10.0.0.1 -p 203.0.113.1 -u netops
#   bgp_advertised_routes.pl -f routers.txt -p 198.51.100.1 -l /var/log/bgp_audit.log

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host_arg, $peer_ip, $username, $logfile, $device_file);
GetOptions(
    'h|host=s'   => \$host_arg,
    'p|peer=s'   => \$peer_ip,
    'u|user=s'   => \$username,
    'l|log=s'    => \$logfile,
    'f|file=s'   => \$device_file,
) or die "Usage: $0 -h <router> -p <peer-ip> [-u user] [-l logfile]\n";

die "Peer IP required (-p)\n" unless $peer_ip;
die "Specify -h <host> or -f <file>\n" unless $host_arg || $device_file;

$username //= $ENV{USER} // 'admin';

my @hosts = $host_arg ? ($host_arg) : do {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    my @lines = grep { /\S/ && !/^#/ } <$fh>;
    chomp @lines;
    @lines;
};

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open logfile $logfile: $!\n";
}

sub output {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub check_advertised_routes {
    my ($host) = @_;
    my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);

    output("=" x 60 . "\n");
    output("Host: $host | Peer: $peer_ip | $timestamp\n");
    output("=" x 60 . "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $host,
            user        => $username,
            raw_pty     => 1,
            timeout     => 30,
        );
    };
    if ($@) {
        output("ERROR: Cannot create SSH session to $host: $@\n");
        return;
    }

    my $login_output = eval { $ssh->login() };
    if ($@ || !defined $login_output) {
        output("ERROR: SSH login failed to $host: " . ($@ // 'unknown') . "\n");
        return;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('\$|#|>', 5);

    $ssh->send("show bgp neighbors $peer_ip advertised-routes");
    my $output = $ssh->waitfor('\$|#|>', 45) // '';

    if ($output =~ /neighbor.*not found|invalid.*address|%\s*Error/i) {
        output("ERROR: Peer $peer_ip not found on $host\n");
        $ssh->close();
        return;
    }

    my ($prefix_count, %as_paths, @leaked_specifics);
    my @prefixes;

    for my $line (split /\n/, $output) {
        next unless $line =~ /^\s*[*>]/;
        if ($line =~ m{
            ^\s*[*>si\s]+        # status codes
            (\d+\.\d+\.\d+\.\d+  # prefix
            (?:/\d+)?)           # mask
        }x) {
            my $prefix = $1;
            push @prefixes, $prefix;
            $prefix_count++;
            if ($line =~ /\{?([\d\s]+)\}?\s+\d+\s+\d+\s+\d+\s+[ie?]/) {
                my $aspath = $1;
                $aspath =~ s/^\s+|\s+$//g;
                $as_paths{$aspath}++ if $aspath;
            }
        }
    }

    for my $p (@prefixes) {
        my ($net, $len) = split '/', $p;
        $len //= 32;
        if ($len > 24) {
            push @leaked_specifics, $p;
        }
    }

    output(sprintf("Prefixes advertised to %s: %d\n", $peer_ip, $prefix_count // 0));

    if (@leaked_specifics) {
        output("\nWARNING: Long prefixes (>24) being advertised:\n");
        output("  $_\n") for @leaked_specifics;
    }

    if (%as_paths) {
        output("\nAS-path origin summary:\n");
        for my $aspath (sort keys %as_paths) {
            output(sprintf("  %-40s  %d prefix(es)\n", $aspath || '(local)', $as_paths{$aspath}));
        }
    }

    $ssh->send('exit');
    $ssh->close();
    output("\n");
}

check_advertised_routes($_) for @hosts;
close $log_fh if $log_fh;
```