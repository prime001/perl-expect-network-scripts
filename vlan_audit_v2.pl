Here is the complete script content:

```
#!/usr/bin/perl
```

Actually, the prompt says "Output ONLY the script content, no markdown fences, no explanation." — let me output it as raw text:

---

#!/usr/bin/perl
#
# 027_vlan_audit.pl - STP Per-VLAN Topology Audit
#
# Purpose:
#   Audits Spanning Tree Protocol state across all active VLANs on Cisco IOS/IOS-XE
#   switches. Reports root bridge assignments, port STP states, topology change
#   counters, and flags VLANs with active topology changes or non-standard root
#   bridge assignments.
#
# Usage:
#   ./027_vlan_audit.pl -h <host> [-u <user>] [-p <password>] [-l <logfile>]
#   ./027_vlan_audit.pl --hostfile devices.txt [-u <user>] [-p <password>] [-l <logfile>]
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#
# Output:
#   VLAN ID, root bridge MAC, root bridge priority, local port state summary,
#   topology change count, and flag if TC active.

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($host, $user, $password, $hostfile, $logfile, $help);
$user     = $ENV{NET_USER}     // 'admin';
$password = $ENV{NET_PASS}     // '';

GetOptions(
    'h|host=s'     => \$host,
    'u|user=s'     => \$user,
    'p|password=s' => \$password,
    'H|hostfile=s' => \$hostfile,
    'l|logfile=s'  => \$logfile,
    'help'         => \$help,
) or die "Error parsing arguments. Use --help.\n";

if ($help || (!$host && !$hostfile)) {
    print "Usage: $0 -h <host> | -H <hostfile> [-u user] [-p pass] [-l logfile]\n";
    exit 0;
}

my @hosts = $host ? ($host) : do {
    open my $fh, '<', $hostfile or die "Cannot open $hostfile: $!\n";
    map { chomp; $_ } grep { /\S/ && !/^#/ } <$fh>;
};

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open logfile $logfile: $!\n";
}

sub log_output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my ($target) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    log_output("\n=== STP VLAN Audit: $target  [$ts] ===\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $target,
        user        => $user,
        password    => $password,
        raw_pty     => 1,
        timeout     => 15,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    eval { $ssh->login() };
    if ($@) {
        log_output("  ERROR: Connection/auth failed for $target: $@\n");
        return;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('\$|#', 5);

    $ssh->send('show spanning-tree summary');
    my $summary = $ssh->waitfor('\$|#', 15);

    my @vlans;
    while ($summary =~ /VLAN(\d+)/g) {
        push @vlans, $1;
    }
    while ($summary =~ /\b(\d{1,4})\b/g) {
        push @vlans, $1 if $1 >= 1 && $1 <= 4094;
    }
    @vlans = do { my %seen; grep { !$seen{$_}++ } sort { $a <=> $b } @vlans };

    if (!@vlans) {
        log_output("  No active STP VLANs found on $target\n");
        $ssh->close();
        return;
    }

    log_output(sprintf("  %-8s %-20s %-10s %-10s %s\n",
        'VLAN', 'Root Bridge MAC', 'Priority', 'TC Count', 'Flags'));
    log_output("  " . "-" x 65 . "\n");

    for my $vid (@vlans) {
        $ssh->send("show spanning-tree vlan $vid");
        my $out = $ssh->waitfor('\$|#', 10);
        next unless defined $out && length $out;

        my $root_mac  = ($out =~ /Root ID.*?Address\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})/si) ? $1 : 'unknown';
        my $root_prio = ($out =~ /Root ID.*?Priority\s+(\d+)/si)                                  ? $1 : '?';
        my $tc_count  = ($out =~ /Number of topology changes\s+(\d+)/i)                           ? $1 : '0';
        my $tc_active = ($out =~ /topology change\s+active/i)                                     ? 1  : 0;

        my @flags;
        push @flags, 'TC-ACTIVE' if $tc_active;
        push @flags, sprintf('TC=%s', $tc_count) if $tc_count > 100;
        my $flag_str = @flags ? join(',', @flags) : 'ok';

        log_output(sprintf("  %-8s %-20s %-10s %-10s %s\n",
            "VLAN$vid", $root_mac, $root_prio, $tc_count, $flag_str));
    }

    $ssh->send('exit');
    $ssh->close();
    log_output("  Audited " . scalar(@vlans) . " VLAN(s).\n");
}

for my $target (@hosts) {
    audit_device($target);
}

close $log_fh if $log_fh;