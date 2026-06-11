```perl
#!/usr/bin/perl
#
# trunk_vlan_audit.pl - Cisco IOS trunk port VLAN allowed-list auditor
#
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE switches via SSH and audits trunk
#   port state: encapsulation, native VLAN, allowed VLAN ranges, and active
#   VLAN sets. Flags native VLAN 1 usage (security risk) and trunks carrying
#   no active VLANs (potential misconfiguration).
#
# Usage:
#   ./trunk_vlan_audit.pl -H 192.168.1.1 -u admin -p secret
#   ./trunk_vlan_audit.pl -f switches.txt -u netops -p secret -e enablepass -l audit.log
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   Read-only SSH access sufficient; -e enables privileged exec if needed
#   Tested: Cisco IOS 12.2+, IOS-XE 16.x/17.x

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($single_host, $host_file, $username, $password, $enable_pass, $log_file, $timeout);

GetOptions(
    'H|host=s'    => \$single_host,
    'f|file=s'    => \$host_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'e|enable=s'  => \$enable_pass,
    'l|log=s'     => \$log_file,
    't|timeout=i' => \$timeout,
) or die usage();

$timeout //= 30;
die usage() unless ($single_host || $host_file) && $username && $password;

my @hosts;
if ($single_host) {
    push @hosts, $single_host;
} else {
    open my $fh, '<', $host_file or die "Cannot open '$host_file': $!\n";
    while (<$fh>) { chomp; push @hosts, $_ unless /^\s*(?:#|$)/ }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or warn "Cannot open log '$log_file': $!\n";
}

sub log_out { print @_; print $log_fh @_ if $log_fh }
sub usage   { "Usage: $0 -H host|-f file -u user -p pass [-e enable] [-l log] [-t secs]\n" }

log_out("=== Trunk VLAN Audit - " . strftime('%Y-%m-%d %H:%M:%S', localtime) . " ===\n\n");

for my $host (@hosts) {
    log_out("Host: $host\n" . "-" x 62 . "\n");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $host,
            user     => $username,
            password => $password,
            raw_pty  => 1,
            timeout  => $timeout,
        );
        $ssh->login();
    };

    if ($@) {
        my $err = $@;
        if    ($err =~ /timed.?out/i)           { log_out("  FAIL: Connection timed out\n\n") }
        elsif ($err =~ /auth|password|denied/i) { log_out("  FAIL: Authentication failed\n\n") }
        else                                    { log_out("  FAIL: $err\n\n") }
        next;
    }

    if ($enable_pass) {
        $ssh->send("enable");
        $ssh->waitfor('Password:', 10) or log_out("  WARN: enable prompt not seen\n");
        $ssh->send($enable_pass);
        $ssh->waitfor('#', 10)         or log_out("  WARN: enable mode not confirmed\n");
    }

    $ssh->exec("terminal length 0");
    my $trunk_out = $ssh->exec("show interfaces trunk");

    my (%trunks, $section);

    for my $line (split /\n/, $trunk_out) {
        $section = 'header'  if $line =~ /^Port\s+Mode\s+Encapsulation/;
        $section = 'allowed' if $line =~ /^Port\s+Vlans allowed on trunk/;
        $section = 'active'  if $line =~ /^Port\s+Vlans allowed and active/;
        $section = 'pruned'  if $line =~ /^Port\s+Vlans in spanning tree/;
        next unless $line =~ /^(\S+)\s+(.*\S)/ && $1 ne 'Port';

        my ($port, $rest) = ($1, $2);
        if ($section eq 'header') {
            my ($mode, $encap, $status, $native) = split /\s+/, $rest;
            $trunks{$port} = { mode => $mode//'?', encap => $encap//'?',
                               status => $status//'?', native => $native//'?' };
        }
        $trunks{$port}{allowed} = $rest if $section eq 'allowed' && exists $trunks{$port};
        $trunks{$port}{active}  = $rest if $section eq 'active'  && exists $trunks{$port};
        $trunks{$port}{pruned}  = $rest if $section eq 'pruned'  && exists $trunks{$port};
    }

    unless (keys %trunks) {
        log_out("  No trunk interfaces found.\n\n");
        $ssh->close();
        next;
    }

    log_out(sprintf("  %-20s %-8s %-12s %-8s %s\n", 'Interface','Status','Encap','Native','Flags'));
    log_out("  " . "-" x 60 . "\n");

    my ($warn_native1, $warn_no_active) = (0, 0);

    for my $port (sort keys %trunks) {
        my $t = $trunks{$port};
        my @flags;
        push @flags, 'NATIVE=1!'       if ($t->{native}//'') eq '1';
        push @flags, 'NO-ACTIVE-VLANS' if ($t->{active}//'') =~ /^\s*none\s*$/i;
        $warn_native1++   if grep { /NATIVE/ } @flags;
        $warn_no_active++ if grep { /NO-ACTIVE/ } @flags;
        log_out(sprintf("  %-20s %-8s %-12s %-8s %s\n",
            $port, $t->{status}, $t->{encap}, $t->{native},
            @flags ? join(' ', @flags) : 'ok'));
        if ($t->{active} && $t->{active} !~ /none/i) {
            log_out(sprintf("    active VLANs: %s\n", $t->{active}));
        }
    }

    log_out(sprintf("\n  Summary: %d trunk(s) | %d native-VLAN-1 warning(s) | %d no-active-VLANs\n",
        scalar keys %trunks, $warn_native1, $warn_no_active));
    log_out("  ACTION: Change native VLAN from 1 on flagged trunks (CVE-2005-4258 / VLAN hopping)\n")
        if $warn_native1;
    log_out("\n");

    $ssh->close();
}

close $log_fh if $log_fh;
log_out("=== Audit complete ===\n");
```