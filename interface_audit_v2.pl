#!/usr/bin/perl
# =============================================================================
# acl_audit.pl - Network ACL Audit Tool
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and audits access control
#   lists (ACLs). Collects ACL definitions, hit counts, and flags ACEs with
#   zero hits (potentially dead rules), implicit deny stats, and ACLs applied
#   to interfaces. Useful for security reviews and firewall rule cleanup.
#
# Usage:
#   Single device:   ./acl_audit.pl -h 192.168.1.1 -u admin [-p pass] [-l logfile]
#   Device file:     ./acl_audit.pl -f devices.txt -u admin [-p pass] [-l logfile]
#   With enable:     ./acl_audit.pl -h 192.168.1.1 -u admin -e enablepass
#
# Prerequisites:
#   cpan Net::SSH::Expect
#
# devices.txt format: one IP or hostname per line, lines starting with # ignored
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $enable_pass, $logfile, $help);
my $timeout = 30;

GetOptions(
    'h=s' => \$host,
    'f=s' => \$file,
    'u=s' => \$user,
    'p=s' => \$pass,
    'e=s' => \$enable_pass,
    'l=s' => \$logfile,
    't=i' => \$timeout,
    'help' => \$help,
) or die "Usage: $0 -h HOST | -f FILE -u USER [-p PASS] [-e ENABLE] [-l LOGFILE]\n";

if ($help || !$user || (!$host && !$file)) {
    print "Usage: $0 -h HOST | -f FILE -u USER [-p PASS] [-e ENABLE] [-l LOGFILE] [-t TIMEOUT]\n";
    exit 0;
}

# Prompt for password if not provided
unless ($pass) {
    print "Password: ";
    system('stty', '-echo');
    chomp($pass = <STDIN>);
    system('stty', 'echo');
    print "\n";
}

my @devices;
if ($host) {
    push @devices, $host;
} elsif ($file) {
    open(my $fh, '<', $file) or die "Cannot open device file '$file': $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>', $logfile) or die "Cannot open log file '$logfile': $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=" x 70);
output("ACL Audit Report - $timestamp");
output("=" x 70);

for my $device (@devices) {
    audit_device($device);
}

close $log_fh if $log_fh;
exit 0;

sub audit_device {
    my ($dev) = @_;
    output("\n--- Device: $dev ---");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host        => $dev,
            user        => $user,
            password    => $pass,
            raw_pty     => 1,
            timeout     => $timeout,
        );
        $ssh->login();
    };
    if ($@) {
        output("  ERROR: Connection failed to $dev: $@");
        return;
    }

    # Detect prompt and disable paging
    my $prompt = '[\$#>]\s*$';
    $ssh->send('terminal length 0');
    $ssh->waitfor($prompt, 5);

    # Enter enable mode if needed
    if ($enable_pass) {
        $ssh->send('enable');
        my $result = $ssh->waitfor('(?:assword|#)', 5);
        if ($result =~ /assword/) {
            $ssh->send($enable_pass);
            $ssh->waitfor($prompt, 5);
        }
    }

    # Verify we have privileged access
    $ssh->send('show privilege');
    my $priv_out = $ssh->waitfor($prompt, 10);
    unless ($priv_out =~ /level\s+1[0-5]/i) {
        output("  WARN: May not have privileged access - ACL details may be incomplete");
    }

    # Get ACL hit counts
    $ssh->send('show ip access-lists');
    my $acl_out = $ssh->waitfor($prompt, 30);

    # Get interface ACL bindings
    $ssh->send('show ip interface | include (Internet|line proto|Inbound|Outbound)');
    my $intf_out = $ssh->waitfor($prompt, 30);

    $ssh->send('exit');

    parse_acls($dev, $acl_out, $intf_out);
}

sub parse_acls {
    my ($dev, $acl_raw, $intf_raw) = @_;

    my %acls;
    my $current_acl = '';

    for my $line (split /\r?\n/, $acl_raw) {
        $line =~ s/\r//g;

        if ($line =~ /^(?:Standard|Extended)\s+IP\s+access\s+list\s+(\S+)/i) {
            $current_acl = $1;
            $acls{$current_acl}{type}  = ($line =~ /Extended/i) ? 'extended' : 'standard';
            $acls{$current_acl}{aces}  = 0;
            $acls{$current_acl}{hits}  = 0;
            $acls{$current_acl}{zero_hit_aces} = 0;
        } elsif ($current_acl && $line =~ /^\s+\d+\s+/) {
            $acls{$current_acl}{aces}++;
            my ($hits) = $line =~ /\((\d+)\s+match(?:es)?\)/;
            $hits //= 0;
            $acls{$current_acl}{hits} += $hits;
            $acls{$current_acl}{zero_hit_aces}++ if $hits == 0;
        }
    }

    # Parse interface bindings
    my %bound_acls;
    my $current_intf = '';
    for my $line (split /\r?\n/, $intf_raw) {
        $line =~ s/\r//g;
        if ($line =~ /^(\S+)\s+is\s+/) {
            $current_intf = $1;
        } elsif ($line =~ /(?:Inbound|Outbound)\s+access\s+list\s+is\s+(\S+)/i) {
            my $acl_name = $1;
            next if $acl_name eq 'not set';
            push @{$bound_acls{$acl_name}}, $current_intf;
        }
    }

    if (!%acls) {
        output("  No IP access lists found on $dev");
        return;
    }

    output(sprintf("  %-30s %-10s %-6s %-10s %-10s %s",
        'ACL Name', 'Type', 'ACEs', 'Total Hits', 'Zero-Hit', 'Applied To'));
    output("  " . "-" x 90);

    my $total_acls     = 0;
    my $unused_acls    = 0;
    my $unbound_acls   = 0;

    for my $name (sort keys %acls) {
        $total_acls++;
        my $a       = $acls{$name};
        my $applied = join(', ', @{$bound_acls{$name} // []}) || 'NOT BOUND';
        my $flag    = '';
        $flag .= ' [UNUSED]'   if $a->{hits} == 0 && $a->{aces} > 0;
        $flag .= ' [UNBOUND]'  if $applied eq 'NOT BOUND';

        $unused_acls++  if $a->{hits} == 0 && $a->{aces} > 0;
        $unbound_acls++ if $applied eq 'NOT BOUND';

        output(sprintf("  %-30s %-10s %-6d %-10d %-10d %s%s",
            $name,
            $a->{type},
            $a->{aces},
            $a->{hits},
            $a->{zero_hit_aces},
            $applied,
            $flag,
        ));
    }

    output("  " . "-" x 90);
    output("  Summary: $total_acls ACLs | $unused_acls with zero hits | $unbound_acls not bound to any interface");
}

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}