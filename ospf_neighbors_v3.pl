Writing a Spanning Tree Protocol audit script — distinct from all existing scripts in the repo.

```perl
#!/usr/bin/perl
#
# stp_audit.pl - Spanning Tree Protocol Topology Auditor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE switches via SSH and audits spanning tree
#   topology: root bridge ownership, port states, blocked/alternate ports,
#   topology change counters, and STP mode. Flags instability indicators
#   that could indicate a loop risk or recent convergence event.
#
# Usage:
#   ./stp_audit.pl -h <host> [-u <user>] [-p <pass>] [-l <logfile>] [-t <secs>]
#   ./stp_audit.pl -f <hosts_file> [-u <user>] [-p <pass>] [-l <logfile>]
#
#   Environment variables: NET_USER, NET_PASS (override -u/-p defaults)
#
# Prerequisites:
#   cpan Expect Getopt::Long
#   SSH key or password access with at minimum 'show' privilege level
#
# Output:
#   Per-device summary: STP mode, root bridge VLANs, blocked ports, TC count
#   Optionally appended to -l logfile with timestamps
#
# Tested against: Cisco IOS 15.x, IOS-XE 16.x/17.x

use strict;
use warnings;
use Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log, $opt_timeout);
$opt_timeout = 30;

GetOptions(
    'h|host=s'    => \$opt_host,
    'f|file=s'    => \$opt_file,
    'u|user=s'    => \$opt_user,
    'p|pass=s'    => \$opt_pass,
    'l|log=s'     => \$opt_log,
    't|timeout=i' => \$opt_timeout,
) or die "Usage: $0 -h <host>|-f <file> [-u user] [-p pass] [-l log] [-t secs]\n";

my $username = $opt_user || $ENV{NET_USER} || 'admin';
my $password = $opt_pass || $ENV{NET_PASS}
    or die "Password required: use -p <pass> or export NET_PASS=<pass>\n";

die "Specify -h <host> or -f <hosts_file>\n" unless $opt_host || $opt_file;

my @devices;
if ($opt_file) {
    open(my $fh, '<', $opt_file) or die "Cannot open $opt_file: $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { s/\s+//gr } <$fh>;
    close $fh;
} else {
    @devices = ($opt_host);
}

my $log_fh;
if ($opt_log) {
    open($log_fh, '>>', $opt_log) or die "Cannot open log $opt_log: $!\n";
}

sub out {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my ($device) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    out("\n" . "=" x 62 . "\n");
    out(sprintf("%-12s %-30s [%s]\n", "Device:", $device, $ts));
    out("=" x 62 . "\n");

    my $exp = Expect->new();
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 -l $username $device")) {
        out("  ERROR: Cannot spawn SSH session to $device\n");
        return;
    }

    my $authed = $exp->expect($opt_timeout,
        [ qr/[Pp]assword:/,    sub { $exp->send("$password\n"); exp_continue; } ],
        [ qr/yes\/no\)/,       sub { $exp->send("yes\n");       exp_continue; } ],
        [ qr/[#>]\s*$/,        sub { 1; } ],
        [ 'timeout', sub { out("  ERROR: Timeout during login to $device\n"); } ],
        [ 'eof',     sub { out("  ERROR: Connection closed by $device (check credentials/ACL)\n"); } ],
    );

    unless ($authed) {
        $exp->soft_close();
        return;
    }

    $exp->send("terminal length 0\n");
    $exp->expect($opt_timeout, qr/[#>]\s*$/);

    $exp->send("show spanning-tree summary\n");
    my $stp_sum = '';
    $exp->expect($opt_timeout, [ qr/[#>]\s*$/, sub { $stp_sum = $exp->before(); } ]);

    $exp->send("show spanning-tree\n");
    my $stp_detail = '';
    $exp->expect($opt_timeout, [ qr/[#>]\s*$/, sub { $stp_detail = $exp->before(); } ]);

    $exp->send("exit\n");
    $exp->soft_close();

    # STP mode
    my ($mode) = $stp_sum =~ /Switch is in (\S+ \S+ \S+)\s*mode/i;
    ($mode)    = $stp_sum =~ /Switch is in (\S+ \S+)\s*mode/i unless $mode;
    out(sprintf("  %-20s %s\n", "STP mode:", $mode // 'unknown'));

    # Root bridge ownership
    my ($root_vlans) = $stp_sum =~ /Root bridge for:\s*(.+)/i;
    if ($root_vlans) {
        $root_vlans =~ s/\s+$//;
        out(sprintf("  %-20s %s\n", "Root for VLANs:", $root_vlans));
    } else {
        out(sprintf("  %-20s %s\n", "Root for VLANs:", "none (not root on any VLAN)"));
    }

    # Active STP VLANs
    my @vlans = ($stp_detail =~ /^VLAN(\d+)/mg);
    my $vlan_display = @vlans
        ? scalar(@vlans) . " (" . join(',', (sort {$a<=>$b} @vlans)[0..($#vlans>9?9:$#vlans)]) . (@vlans>10?',...':'') . ")"
        : "0";
    out(sprintf("  %-20s %s\n", "Active STP VLANs:", $vlan_display));

    # Blocked / alternate ports
    my %blocked_ports;
    while ($stp_detail =~ /^\s*(Gi\S+|Fa\S+|Te\S+|Eth\S+|Po\d+)\s+(?:BLK|ALT)\b/mg) {
        $blocked_ports{$1}++;
    }
    my @blk = sort keys %blocked_ports;
    out(sprintf("  %-20s %s\n", "Blocked/Alt ports:",
        @blk ? join(', ', @blk) : "none (verify topology if unexpected)"));

    # Topology change count — non-zero is a yellow flag
    my ($tc_total) = $stp_sum =~ /(\d+)\s+topology change/i;
    if (defined $tc_total && $tc_total > 0) {
        out(sprintf("  %-20s %d  ** WARN: topology instability indicator **\n",
            "Topology changes:", $tc_total));
    } else {
        out(sprintf("  %-20s %s\n", "Topology changes:", $tc_total // '0'));
    }

    # Portfast / BPDU guard summary
    my ($pf_count)  = $stp_sum =~ /(\d+)\s+portfast/i;
    my ($bpdu_grd)  = $stp_sum =~ /BPDU Guard is (enabled|disabled)/i;
    out(sprintf("  %-20s %s\n", "Portfast ports:", $pf_count // 'n/a'));
    out(sprintf("  %-20s %s\n", "BPDU Guard global:", $bpdu_grd // 'n/a'));
}

audit_device($_) for @devices;
out("\nAudit complete: " . scalar(@devices) . " device(s) processed.\n");
close $log_fh if $log_fh;
```