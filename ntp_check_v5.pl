#!/usr/bin/perl
use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

# cdp_lldp_neighbors.pl - Cisco CDP/LLDP Neighbor Discovery Tool
#
# Purpose:
#   Connects to network devices via SSH and collects CDP and LLDP neighbor
#   information to verify topology adjacencies, document connected devices,
#   and detect unexpected neighbors. Useful for network audits, change
#   validation, and building topology maps.
#
# Prerequisites:
#   - Perl modules: Expect, Getopt::Long
#   - SSH key auth or password (prompted if not in env)
#   - CDP and/or LLDP enabled on target devices
#
# Usage:
#   ./cdp_lldp_neighbors.pl -h 192.168.1.1
#   ./cdp_lldp_neighbors.pl -f devices.txt -u admin -l neighbors.log
#   ./cdp_lldp_neighbors.pl -h 10.0.0.1 -u netops -p secret -t 30
#
# Environment:
#   NET_USER  - SSH username (overridden by -u)
#   NET_PASS  - SSH password (overridden by -p)

my ($host, $hostfile, $username, $password, $logfile, $timeout, $help);
my $protocol = 'both';

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$hostfile,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$logfile,
    't|timeout=i'  => \$timeout,
    'proto=s'      => \$protocol,
    'help'         => \$help,
) or die "Error parsing options. Use --help for usage.\n";

if ($help) {
    print "Usage: $0 [-h host | -f file] [-u user] [-p pass] [-l logfile] [-t timeout] [--proto cdp|lldp|both]\n";
    exit 0;
}

die "Specify a host (-h) or host file (-f)\n" unless $host || $hostfile;

$username //= $ENV{NET_USER} // do { print "Username: "; chomp(my $u = <STDIN>); $u };
$password //= $ENV{NET_PASS} // do {
    system('stty -echo');
    print "Password: ";
    chomp(my $p = <STDIN>);
    system('stty echo');
    print "\n";
    $p
};
$timeout //= 20;

my @devices = $host ? ($host) : do {
    open my $fh, '<', $hostfile or die "Cannot open $hostfile: $!\n";
    map { chomp; $_ } grep { /\S/ && !/^#/ } <$fh>;
};

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=" x 60);
output("CDP/LLDP Neighbor Discovery  |  $ts");
output("Devices: " . scalar(@devices) . "  |  Protocol: $protocol");
output("=" x 60);

for my $device (@devices) {
    output("\n--- $device ---");
    check_neighbors($device);
}

output("\nDone.");
close $log_fh if $log_fh;

sub check_neighbors {
    my ($dev) = @_;

    my $exp = Expect->new;
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${username}\@${dev}")) {
        output("  ERROR: Failed to spawn SSH for $dev");
        return;
    }

    my $logged_in = 0;
    $exp->expect($timeout,
        [ qr/[Pp]assword[: ]+/,  sub { $exp->send("$password\n"); exp_continue; } ],
        [ qr/yes\/no/,            sub { $exp->send("yes\n");       exp_continue; } ],
        [ qr/[#>]\s*$/,           sub { $logged_in = 1; } ],
        [ qr/onnection refused/,  sub { output("  ERROR: Connection refused"); } ],
        [ qr/uthentication fail/, sub { output("  ERROR: Authentication failed"); } ],
        [ timeout => sub { output("  ERROR: Timeout during login"); } ],
    );

    unless ($logged_in) {
        $exp->soft_close;
        return;
    }

    $exp->send("terminal length 0\n");
    $exp->expect(5, qr/[#>]\s*$/);

    if ($protocol =~ /cdp|both/) {
        $exp->send("show cdp neighbors detail\n");
        my $out = '';
        $exp->expect($timeout,
            [ qr/[#>]\s*$/, sub { $out = $exp->before; } ],
            [ timeout =>    sub { output("  WARN: Timeout on CDP command"); } ],
        );
        parse_cdp($out) if $out;
    }

    if ($protocol =~ /lldp|both/) {
        $exp->send("show lldp neighbors detail\n");
        my $out = '';
        $exp->expect($timeout,
            [ qr/[#>]\s*$/, sub { $out = $exp->before; } ],
            [ timeout =>    sub { output("  WARN: Timeout on LLDP command"); } ],
        );
        parse_lldp($out) if $out;
    }

    $exp->send("exit\n");
    $exp->soft_close;
}

sub parse_cdp {
    my ($raw) = @_;
    my @blocks = split /(?=Device ID:)/, $raw;
    my $count = 0;
    for my $block (@blocks) {
        next unless $block =~ /Device ID:/;
        my ($nbr)  = $block =~ /Device ID:\s*(\S+)/;
        my ($intf) = $block =~ /Interface:\s*(\S+)/;
        my ($port) = $block =~ /Port ID.*?:\s*(\S+)/;
        my ($plat) = $block =~ /Platform:\s*([^,\n]+)/;
        my ($ip)   = $block =~ /IP address:\s*(\S+)/;
        $nbr  //= 'unknown'; $intf //= '?'; $port //= '?';
        $plat = defined $plat ? (split /,/, $plat)[0] : 'unknown';
        $ip //= 'N/A';
        output(sprintf "  [CDP] %-20s  %-20s -> %-20s  IP:%-16s  %s",
            $nbr, $intf, $port, $ip, $plat);
        $count++;
    }
    output("  [CDP] No neighbors found") if $count == 0;
}

sub parse_lldp {
    my ($raw) = @_;
    my @blocks = split /(?=Local Intf:|Interface:)/, $raw;
    my $count = 0;
    for my $block (@blocks) {
        next unless $block =~ /System Name:|Port ID:/;
        my ($local) = $block =~ /(?:Local Intf|Interface):\s*(\S+)/;
        my ($nbr)   = $block =~ /System Name:\s*(\S+)/;
        my ($port)  = $block =~ /Port ID:\s*(\S+)/;
        my ($desc)  = $block =~ /System Description:\s*([^\n]+)/;
        $local //= '?'; $nbr //= 'unknown'; $port //= '?'; $desc //= '';
        $desc =~ s/\s+/ /g; $desc = substr($desc, 0, 40);
        output(sprintf "  [LLDP] %-20s  %-20s -> %-20s  %s",
            $nbr, $local, $port, $desc);
        $count++;
    }
    output("  [LLDP] No neighbors found") if $count == 0;
}

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}