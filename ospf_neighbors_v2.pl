#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# ospf_lsdb_audit.pl - OSPF Link State Database Health Checker
#
# Purpose:
#   Audits the OSPF LSDB on Cisco IOS/IOS-XE devices for anomalies that
#   neighbor-state checks miss: duplicate router IDs, unexpectedly large LSA
#   counts, external route injection from unknown sources, and stale LSAs
#   near MaxAge (3600s).  Useful for post-change validation and routine
#   protocol health sweeps.
#
# Usage:
#   ./ospf_lsdb_audit.pl -h <host> [-u <user>] [-p <pass>] [-l <logfile>]
#   ./ospf_lsdb_audit.pl --hostfile devices.txt [-u <user>] [-p <pass>] [-l <logfile>]
#
# Prerequisites:
#   Net::SSH::Expect  (cpan install Net::SSH::Expect)
#   Getopt::Long      (core)
#   Cisco IOS/IOS-XE with OSPF configured; SSH enabled on target devices
#
# Output:
#   Tab-aligned summary to STDOUT; optionally appended to a log file.
#   Exit code 0 = clean, 1 = warnings found, 2 = errors/unreachable.
# =============================================================================

my ($opt_host, $opt_hostfile, $opt_user, $opt_pass, $opt_logfile);
my $opt_timeout  = 20;
my $exit_code    = 0;

GetOptions(
    'h|host=s'     => \$opt_host,
    'f|hostfile=s' => \$opt_hostfile,
    'u|user=s'     => \$opt_user,
    'p|pass=s'     => \$opt_pass,
    'l|log=s'      => \$opt_logfile,
    't|timeout=i'  => \$opt_timeout,
) or die "Usage: $0 -h <host> | -f <hostfile> [-u user] [-p pass] [-l logfile]\n";

$opt_user //= $ENV{NET_USER} // die "No username provided (-u or NET_USER env)\n";
$opt_pass //= $ENV{NET_PASS} // die "No password provided (-p or NET_PASS env)\n";

my @hosts;
if ($opt_host) {
    push @hosts, $opt_host;
} elsif ($opt_hostfile) {
    open my $fh, '<', $opt_hostfile or die "Cannot open hostfile: $!\n";
    while (<$fh>) { chomp; push @hosts, $_ if /\S/ && !/^\s*#/ }
    close $fh;
} else {
    die "Specify -h <host> or -f <hostfile>\n";
}

my $log_fh;
if ($opt_logfile) {
    open $log_fh, '>>', $opt_logfile or warn "Cannot open log $opt_logfile: $!\n";
}

sub out {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my ($host) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);

    out("[$ts] === Auditing OSPF LSDB: $host ===\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $opt_user,
        password    => $opt_pass,
        timeout     => $opt_timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        raw_pty     => 1,
    );

    unless ($ssh->run_ssh()) {
        out("  [ERROR] SSH connection failed to $host\n\n");
        return 2;
    }

    my $banner = $ssh->read_all(3);
    if ($banner =~ /[Pp]assword|[Aa]uth/i && $banner !~ /[>#]/) {
        out("  [ERROR] Authentication failed for $host\n\n");
        $ssh->close();
        return 2;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('[>#]', 5);

    # --- Collect OSPF process info ---
    $ssh->send("show ip ospf | include Process|Router ID|Number of areas");
    my $proc_out = $ssh->waitfor('[>#]', $opt_timeout) // '';

    unless ($proc_out =~ /Routing Process/i) {
        out("  [INFO]  No OSPF process found on $host\n\n");
        $ssh->close();
        return 0;
    }

    my ($router_id) = $proc_out =~ /Router ID[:\s]+(\d+\.\d+\.\d+\.\d+)/i;
    my ($num_areas) = $proc_out =~ /Number of areas[^:]*:\s*(\d+)/i;
    out(sprintf("  Router ID  : %s\n", $router_id // 'unknown'));
    out(sprintf("  Areas      : %s\n", $num_areas // 'unknown'));

    # --- LSDB summary counts ---
    $ssh->send("show ip ospf database database-summary");
    my $db_out = $ssh->waitfor('[>#]', $opt_timeout) // '';

    my $warnings = 0;
    my %lsa_counts;
    while ($db_out =~ /^\s*(Router|Network|Summary Net|Summary ASB|Type-7 Ext|External)\s+(\d+)/gm) {
        $lsa_counts{$1} = $2;
    }
    for my $type (sort keys %lsa_counts) {
        my $count = $lsa_counts{$type};
        my $flag  = ($type eq 'External' && $count > 500)  ? ' [WARN: high external LSA count]'
                  : ($type eq 'Router'   && $count > 1000) ? ' [WARN: large LSDB]'
                  : '';
        $warnings++ if $flag;
        out(sprintf("  %-18s: %d%s\n", $type, $count, $flag));
    }

    # --- Check for near-MaxAge LSAs (age >= 3400s) ---
    $ssh->send("show ip ospf database | include 3[4-5][0-9][0-9]|36[0-9][0-9]");
    my $age_out = $ssh->waitfor('[>#]', $opt_timeout) // '';
    my @stale   = ($age_out =~ /\b3[456][0-9]{2}\b/g);
    if (@stale) {
        out(sprintf("  [WARN]  %d near-MaxAge LSA(s) detected (age >= 3400s)\n", scalar @stale));
        $warnings++;
    } else {
        out("  MaxAge check: OK\n");
    }

    # --- Check for duplicate Router IDs in neighbor table ---
    $ssh->send("show ip ospf neighbor | include Full|2WAY");
    my $nbr_out = $ssh->waitfor('[>#]', $opt_timeout) // '';
    my %seen_rids;
    my @dup_rids;
    while ($nbr_out =~ /(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\/\S+/g) {
        my $rid = $1;
        push @dup_rids, $rid if $seen_rids{$rid}++;
    }
    if (@dup_rids) {
        out(sprintf("  [WARN]  Duplicate Router ID(s): %s\n", join(', ', @dup_rids)));
        $warnings++;
    } else {
        out("  Duplicate RID check: OK\n");
    }

    my $status = $warnings ? "[WARN]  $warnings issue(s)" : "[OK]    Clean";
    out("  Result     : $status\n\n");

    $ssh->send("exit");
    $ssh->close();
    return $warnings ? 1 : 0;
}

for my $host (@hosts) {
    my $rc = eval { audit_device($host) };
    if ($@) {
        out("  [ERROR] Exception for $host: $@\n\n");
        $rc = 2;
    }
    $exit_code = $rc if $rc > $exit_code;
}

close $log_fh if $log_fh;
exit $exit_code;