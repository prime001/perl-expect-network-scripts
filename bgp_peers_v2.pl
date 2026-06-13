```perl
#!/usr/bin/perl
# =============================================================================
# bgp_peer_policy_audit.pl - BGP Neighbor Route Policy Auditor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE routers and audits BGP neighbor route
#   policies: inbound/outbound route-maps, prefix-lists, distribute-lists,
#   and filter-lists applied per peer. Useful for validating policy
#   consistency across a fleet before/after routing changes.
#
# Usage:
#   Single device:  ./bgp_peer_policy_audit.pl -h 10.0.0.1
#   Device list:    ./bgp_peer_policy_audit.pl -f devices.txt
#   With logging:   ./bgp_peer_policy_audit.pl -h 10.0.0.1 -l /tmp/bgp_audit.log
#   Custom creds:   ./bgp_peer_policy_audit.pl -h 10.0.0.1 -u admin -p secret
#
# Output:
#   Per-peer table showing applied inbound/outbound policies for each
#   BGP neighbor. Flags peers with NO policy applied (potential leak risk).
#
# Prerequisites:
#   cpan install Expect
#   SSH key auth or plaintext credentials (--password flag)
#   Device must support: show bgp neighbors (IOS/IOS-XE syntax)
#
# Tested on: Cisco IOS 15.x, IOS-XE 16.x/17.x
# =============================================================================

use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $enable, $logfile, $timeout, $help);
$user    = $ENV{NET_USER} // 'admin';
$pass    = $ENV{NET_PASS} // '';
$enable  = $ENV{NET_ENABLE} // '';
$timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$file,
    'u|user=s'     => \$user,
    'p|password=s' => \$pass,
    'e|enable=s'   => \$enable,
    'l|log=s'      => \$logfile,
    't|timeout=i'  => \$timeout,
    'help'         => \$help,
) or die "Error in arguments. Use --help for usage.\n";

if ($help) {
    system("grep '^#' $0 | head -25");
    exit 0;
}

die "Specify -h <host> or -f <file>\n" unless $host || $file;

my @devices = $host ? ($host) : do {
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    map { chomp; $_ } grep { /\S/ && !/^#/ } <$fh>;
};

my $log_fh;
if ($logfile) {
    open $log_fh, '>', $logfile or die "Cannot open log $logfile: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("# BGP Peer Policy Audit - $ts\n");

for my $device (@devices) {
    output("\n=== $device ===");
    audit_device($device);
}

close $log_fh if $log_fh;

sub audit_device {
    my ($ip) = @_;

    my $exp = Expect->new();
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${user}\@${ip}")) {
        output("ERROR: Failed to spawn SSH for $ip");
        return;
    }

    my $logged_in = 0;
    $exp->expect($timeout,
        [ qr/[Pp]assword:/ => sub {
            $exp->send("$pass\n");
            exp_continue;
        }],
        [ qr/[>#]/ => sub { $logged_in = 1 }],
        [ qr/[Cc]onnection (refused|timed out)/ => sub {
            output("ERROR: Connection failed to $ip");
        }],
        [ qr/[Aa]uth(entication)? (failed|error)/ => sub {
            output("ERROR: Authentication failed on $ip");
        }],
        [ timeout => sub { output("ERROR: Timeout connecting to $ip") }],
    );
    return unless $logged_in;

    # Enter enable mode if needed
    if ($enable) {
        $exp->send("enable\n");
        $exp->expect($timeout, [ qr/[Pp]assword:/ => sub { $exp->send("$enable\n") }]);
        $exp->expect($timeout, '#');
    }

    # Disable paging
    $exp->send("terminal length 0\n");
    $exp->expect($timeout, qr/[>#]/);

    # Collect BGP neighbor detail
    $exp->send("show bgp neighbors\n");
    my $raw = '';
    $exp->expect(60,
        [ qr/[>#]/ => sub { $raw = $exp->before(); exp_continue if length($raw) < 100 }],
        [ timeout => sub { output("ERROR: Command timed out on $ip") }],
    );

    $exp->send("exit\n");
    $exp->soft_close();

    parse_and_display($ip, $raw);
}

sub parse_and_display {
    my ($ip, $raw) = @_;

    my @neighbors;
    my $current;

    for my $line (split /\n/, $raw) {
        if ($line =~ /^BGP neighbor is (\S+)/) {
            push @neighbors, $current if $current;
            $current = { peer => $1, inbound => [], outbound => [] };
        }
        next unless $current;

        # Route-maps
        if ($line =~ /Route map for (incoming|outgoing) advertisements is (\S+)/) {
            my ($dir, $map) = ($1, $2);
            push @{$current->{inbound}},  "route-map:$map" if $dir eq 'incoming';
            push @{$current->{outbound}}, "route-map:$map" if $dir eq 'outgoing';
        }
        # Prefix-lists
        if ($line =~ /Route map for (incoming|outgoing).*prefix-list (\S+)/i) {
            my ($dir, $pl) = ($1, $2);
            push @{$current->{inbound}},  "prefix-list:$pl" if $dir =~ /in/i;
            push @{$current->{outbound}}, "prefix-list:$pl" if $dir =~ /out/i;
        }
        # Distribute-lists
        if ($line =~ /Incoming (update|filter-list) (\S+)/) {
            push @{$current->{inbound}}, "dist-list:$2";
        }
        if ($line =~ /Outgoing (update|filter-list) (\S+)/) {
            push @{$current->{outbound}}, "dist-list:$2";
        }
        # AS-path filter
        if ($line =~ /AS path filter.*(\d+), (\w+)/) {
            my $dir = $2 eq 'in' ? 'inbound' : 'outbound';
            push @{$current->{$dir}}, "as-path-acl:$1";
        }
    }
    push @neighbors, $current if $current;

    if (!@neighbors) {
        output("  No BGP neighbors found (or BGP not configured)");
        return;
    }

    output(sprintf("  %-20s  %-35s  %-35s  %s",
        "Peer", "Inbound Policy", "Outbound Policy", "Flag"));
    output("  " . "-" x 100);

    for my $n (@neighbors) {
        my $in  = @{$n->{inbound}}  ? join(', ', @{$n->{inbound}})  : 'NONE';
        my $out = @{$n->{outbound}} ? join(', ', @{$n->{outbound}}) : 'NONE';
        my $flag = ($in eq 'NONE' || $out eq 'NONE') ? '*** NO POLICY ***' : '';
        output(sprintf("  %-20s  %-35s  %-35s  %s",
            $n->{peer}, $in, $out, $flag));
    }

    my $unfiltered = grep { !@{$_->{inbound}} || !@{$_->{outbound}} } @neighbors;
    output("  Summary: " . scalar(@neighbors) . " peers, $unfiltered with missing policy") if $unfiltered;
}

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}
```