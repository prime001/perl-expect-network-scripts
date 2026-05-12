```perl
#!/usr/bin/perl
#
# cdp_lldp_neighbors.pl - CDP/LLDP Neighbor Discovery and Topology Mapper
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE/NX-OS devices and collects CDP and LLDP
#   neighbor details to map network topology and verify physical connectivity.
#   Useful for auditing switch/router interconnects, finding rogue devices,
#   and validating cabling documentation.
#
# Usage:
#   perl cdp_lldp_neighbors.pl <host> [username] [password]
#   perl cdp_lldp_neighbors.pl -f hosts.txt [username] [password]
#   perl cdp_lldp_neighbors.pl 10.0.0.1 netadmin MyP@ss -o neighbors.log
#
# Output:
#   Prints neighbor table to STDOUT; optionally writes to log file with -o flag.
#
# Prerequisites:
#   cpanm Net::SSH::Expect
#   SSH access with privilege level 1 or higher (no enable required for show)
#
# Environment:
#   NET_USER, NET_PASS env vars used if CLI args omitted.
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config pass_through);
use POSIX qw(strftime);

my ($host_file, $outfile);
GetOptions(
    'f=s' => \$host_file,
    'o=s' => \$outfile,
);

my @hosts;
if ($host_file) {
    open(my $fh, '<', $host_file) or die "Cannot open host file '$host_file': $!\n";
    @hosts = grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
    close $fh;
} elsif (@ARGV) {
    push @hosts, shift @ARGV;
} else {
    die "Usage: $0 [-f hosts.txt] [-o outfile] <host> [user] [pass]\n";
}

my $username = shift @ARGV || $ENV{NET_USER} || 'admin';
my $password = shift @ARGV || $ENV{NET_PASS} || '';
my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);

my $log_fh;
if ($outfile) {
    open($log_fh, '>>', $outfile) or die "Cannot open output file '$outfile': $!\n";
}

sub output {
    my $line = shift;
    print $line, "\n";
    print $log_fh $line, "\n" if $log_fh;
}

sub collect_neighbors {
    my ($host) = @_;
    output("=" x 60);
    output("Host: $host  [Collected: $timestamp]");
    output("=" x 60);

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $username,
        password    => $password,
        raw_pty     => 1,
        timeout     => 15,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        output("  ERROR: SSH connection failed to $host: " . ($@ || 'unknown error'));
        output("");
        return;
    }

    if ($login_output =~ /password/i) {
        output("  ERROR: Authentication failed for $host");
        output("");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#|>', 5);

    for my $cmd ('show cdp neighbors detail', 'show lldp neighbors detail') {
        my $protocol = ($cmd =~ /cdp/) ? 'CDP' : 'LLDP';
        output("\n--- $protocol Neighbors ---");

        $ssh->send($cmd);
        my $result = $ssh->waitfor('\$|#|>', 20);

        if (!defined $result || $result =~ /invalid|error|not enabled/i) {
            output("  $protocol not available or not enabled on this device.");
            next;
        }

        my @entries;
        my %current;

        for my $line (split /\n/, $result) {
            $line =~ s/\r//g;
            next if $line =~ /^\s*$/ || $line =~ /show\s+(cdp|lldp)/;

            if ($line =~ /Device ID:\s*(.+)/i || $line =~ /System Name:\s*(.+)/i) {
                push @entries, {%current} if %current;
                %current = (device => $1);
                $current{device} =~ s/\s+$//;
            } elsif ($line =~ /IP(?:v4)? [Aa]ddress(?:es)?:\s*(.+)/ || $line =~ /Management [Aa]ddress(?:es)?.*?(\d+\.\d+\.\d+\.\d+)/) {
                $current{ip} = $1;
                $current{ip} =~ s/\s+$//;
            } elsif ($line =~ /Interface:\s*([^,]+),\s*Port ID.*?:\s*(.+)/i) {
                $current{local_intf} = $1;
                $current{remote_intf} = $2;
                s/\s+$// for $current{local_intf}, $current{remote_intf};
            } elsif ($line =~ /Platform:\s*([^,]+)/i) {
                $current{platform} = $1;
                $current{platform} =~ s/\s+$//;
            } elsif ($line =~ /System Capabilities:\s*(.+)/i || $line =~ /Capabilities:\s*(.+)/i) {
                $current{capabilities} = $1;
                $current{capabilities} =~ s/\s+$//;
            }
        }
        push @entries, {%current} if %current;

        if (!@entries) {
            output("  No $protocol neighbors found.");
            next;
        }

        for my $n (@entries) {
            output(sprintf("  Neighbor  : %s", $n->{device}      // 'unknown'));
            output(sprintf("  IP Addr   : %s", $n->{ip}          // 'n/a'));
            output(sprintf("  Local Int : %s", $n->{local_intf}  // 'n/a'));
            output(sprintf("  Remote Int: %s", $n->{remote_intf} // 'n/a'));
            output(sprintf("  Platform  : %s", $n->{platform}    // 'n/a'));
            output(sprintf("  Caps      : %s", $n->{capabilities}// 'n/a'));
            output("  " . "-" x 40);
        }
        output("  Total $protocol neighbors: " . scalar @entries);
    }

    $ssh->close();
    output("");
}

collect_neighbors($_) for @hosts;

close $log_fh if $log_fh;
print "Output saved to $outfile\n" if $outfile;
```