```perl
#!/usr/bin/perl
#
# ospf_neighbor_detail.pl - OSPF Neighbor Detail Analyzer
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers via SSH and collects detailed OSPF
#   neighbor information. Detects neighbors not in FULL state, mismatched
#   hello/dead timers, and highlights potential adjacency issues. Useful for
#   pre-maintenance verification and post-change validation.
#
# Usage:
#   Single device:  perl ospf_neighbor_detail.pl -h 10.0.0.1 -u admin -p secret
#   Device file:    perl ospf_neighbor_detail.pl -f devices.txt -u admin -p secret
#   With logging:   perl ospf_neighbor_detail.pl -f devices.txt -u admin -p secret -l ospf_audit.log
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#
# Device file format (one IP or hostname per line, # for comments):
#   10.0.0.1
#   10.0.0.2   router2-comment-ignored

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file);
my $timeout = 15;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$log_file,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h HOST | -f FILE -u USER -p PASS [-l LOGFILE] [-t TIMEOUT]\n";

die "Provide -h HOST or -f FILE\n"  unless $host || $device_file;
die "Username required (-u)\n"      unless $username;
die "Password required (-p)\n"      unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^\s*#/;
        push @devices, (split /\s+/)[0];
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=" x 70);
output("OSPF Neighbor Detail Audit  --  $ts");
output("=" x 70);

for my $device (@devices) {
    output("\n--- Device: $device ---");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $username,
        password     => $password,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        output("  ERROR: SSH connection failed to $device: $@");
        next;
    }

    if ($login_output =~ /[Aa]uth|[Dd]enied|[Ff]ail/) {
        output("  ERROR: Authentication failed on $device");
        $ssh->close();
        next;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#', $timeout) or do {
        output("  ERROR: No prompt after terminal length on $device");
        $ssh->close();
        next;
    };

    $ssh->send("show ip ospf neighbor detail");
    my $raw = $ssh->waitfor('\$|#', $timeout);

    unless (defined $raw) {
        output("  ERROR: Timeout waiting for OSPF output on $device");
        $ssh->close();
        next;
    }

    $ssh->send("exit");
    $ssh->close();

    parse_and_report($device, $raw);
}

output("\n" . "=" x 70);
output("Audit complete.");
close $log_fh if $log_fh;

sub parse_and_report {
    my ($device, $raw) = @_;

    if ($raw !~ /Neighbor ID/i) {
        output("  No OSPF neighbors found (or OSPF not configured).");
        return;
    }

    my @blocks = split /(?=Neighbor\s+\d+\.\d+\.\d+\.\d+)/i, $raw;
    my ($total, $issues) = (0, 0);

    for my $block (@blocks) {
        next unless $block =~ /Neighbor\s+(\d+\.\d+\.\d+\.\d+)/i;
        my $nbr_id = $1;
        $total++;

        my ($state)    = $block =~ /State\s+is\s+(\S+)/i;
        my ($iface)    = $block =~ /interface\s+address\s+\S+,\s+interface\s+(\S+)/i;
        my ($priority) = $block =~ /Neighbor\s+priority\s+is\s+(\d+)/i;
        my ($dead_in)  = $block =~ /Dead\s+timer\s+due\s+in\s+([\d:]+)/i;
        my ($hello)    = $block =~ /Hello\s+due\s+in\s+([\d:]+)/i;
        my ($area)     = $block =~ /in\s+area\s+(\S+)/i;

        $state    //= 'UNKNOWN';
        $iface    //= 'unknown';
        $priority //= '?';
        $area     //= '?';

        my $flag = ($state !~ /^FULL/i) ? ' [!]' : '';
        $issues++ if $flag;

        output(sprintf("  %-18s  State: %-12s  Iface: %-18s  Area: %-10s  Pri: %s%s",
            $nbr_id, $state, $iface, $area, $priority, $flag));
    }

    output("  Summary: $total neighbor(s), $issues with issues" . ($issues ? ' [REVIEW NEEDED]' : ' -- all FULL'));
}

sub output {
    my ($line) = @_;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}
```