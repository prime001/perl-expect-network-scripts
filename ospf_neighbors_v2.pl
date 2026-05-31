#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# ospf_route_verify.pl — OSPF Routing Table Verification
#
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE devices and pulls the OSPF
#   routing table (show ip route ospf).  Summarises intra-area, inter-area,
#   and external routes and optionally validates that a list of expected
#   prefixes is present.  Useful for post-change verification and daily
#   sanity checks.
#
# Usage:
#   ospf_route_verify.pl -h 192.168.1.1 [-h 192.168.1.2 ...] \
#       -u admin -p secret [-f devices.txt] [-e expected.txt] [-l out.log]
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH reachability + credentials with "show" privilege

my (@hosts, $user, $pass, $device_file, $expect_file, $log_file);
my $timeout = 20;

GetOptions(
    'h|host=s'     => \@hosts,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'f|file=s'     => \$device_file,
    'e|expect=s'   => \$expect_file,
    'l|log=s'      => \$log_file,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h HOST -u USER -p PASS [-f devices.txt] [-e prefixes.txt] [-l log]\n";

die "Credentials required: -u USER -p PASS\n" unless $user && $pass;

if ($device_file && open my $fh, '<', $device_file) {
    while (<$fh>) { chomp; push @hosts, $_ if /\S/ && !/^#/ }
    close $fh;
}
die "No hosts specified. Use -h or -f.\n" unless @hosts;

my @expected_prefixes;
if ($expect_file && open my $fh, '<', $expect_file) {
    while (<$fh>) { chomp; push @expected_prefixes, $_ if /\S/ && !/^#/ }
    close $fh;
}

my $LOG;
if ($log_file) {
    open $LOG, '>>', $log_file or warn "Cannot open log $log_file: $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $LOG $msg if $LOG;
}

sub check_device {
    my ($host) = @_;
    out(sprintf "\n=== %s  [%s] ===\n", $host, strftime('%Y-%m-%d %H:%M:%S', localtime));

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    unless ($ssh->run_ssh()) {
        out("  ERROR: SSH connection failed to $host\n");
        return;
    }

    my $login = $ssh->read_all(5);
    if ($login =~ /[Pp]assword/) {
        $ssh->send($pass);
        $ssh->read_all(3);
    }
    if ($login =~ /[Uu]sername/) {
        out("  ERROR: Auth prompt unexpected — check credentials\n");
        $ssh->close();
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->read_all(3);

    $ssh->send("show ip route ospf\n");
    my $raw = $ssh->read_all(10);

    $ssh->send("exit\n");
    $ssh->close();

    my (%counts, @routes);
    for my $line (split /\n/, $raw) {
        if ($line =~ /^\s*O\s+IA\s+(\S+)/) {
            $counts{inter}++; push @routes, $1;
        } elsif ($line =~ /^\s*O\s+E[12]\s+(\S+)/) {
            $counts{external}++; push @routes, $1;
        } elsif ($line =~ /^\s*O\s+(\d+\.\d+\.\d+\.\d+[\/\s])/) {
            $counts{intra}++; push @routes, (split /\s+/, $1)[0];
        }
    }

    $counts{$_} //= 0 for qw(intra inter external);
    out(sprintf "  Intra-area (O):    %d\n",    $counts{intra});
    out(sprintf "  Inter-area (O IA): %d\n",    $counts{inter});
    out(sprintf "  External (O E1/2): %d\n",    $counts{external});
    out(sprintf "  Total OSPF routes: %d\n",    $counts{intra} + $counts{inter} + $counts{external});

    if (@expected_prefixes) {
        out("  --- Prefix verification ---\n");
        my $missing = 0;
        for my $prefix (@expected_prefixes) {
            my $found = grep { index($_, $prefix) == 0 } @routes;
            if ($found) {
                out("  [OK]     $prefix\n");
            } else {
                out("  [MISS]   $prefix  *** NOT IN TABLE ***\n");
                $missing++;
            }
        }
        out(sprintf "  Result: %d/%d expected prefixes present\n",
            scalar(@expected_prefixes) - $missing, scalar(@expected_prefixes));
    }
}

out(sprintf "OSPF Route Verification — %s\n", strftime('%Y-%m-%d %H:%M:%S', localtime));
out("Devices: " . join(', ', @hosts) . "\n");

check_device($_) for @hosts;

out("\nDone.\n");
close $LOG if $LOG;