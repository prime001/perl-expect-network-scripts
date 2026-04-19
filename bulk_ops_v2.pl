```perl
#!/usr/bin/perl
#
# acl_audit.pl - Bulk ACL Audit Tool for Cisco IOS Devices
#
# Purpose:
#   Connects to one or more network devices and audits access control lists
#   (ACLs). Reports ACL names, entry counts, and flags any ACLs containing
#   permit-any rules that may represent security risks.
#
# Usage:
#   Single device:  perl acl_audit.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    perl acl_audit.pl -f devices.txt -u admin -p secret
#   With logging:   perl acl_audit.pl -f devices.txt -u admin -p secret -l acl_audit.log
#
# Prerequisites:
#   cpan Net::SSH::Expect
#
# Device file format (one IP/hostname per line, blank lines and # comments ignored):
#   192.168.1.1
#   192.168.1.2
#   # This device is offline
#   router-core-01
#
# Author: Network Automation Portfolio
# Version: 1.0

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file);
my $timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$log_file,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 [-h host|-f file] -u user -p pass [-l logfile] [-t timeout]\n";

die "ERROR: Provide -h <host> or -f <file>\n" unless $host || $device_file;
die "ERROR: -u username required\n" unless $username;
die "ERROR: -p password required\n" unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "ERROR: Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^\s*#/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or warn "WARN: Cannot open log $log_file: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=" x 60);
output("ACL Audit Report - $timestamp");
output("Devices to audit: " . scalar(@devices));
output("=" x 60);

my %summary = (processed => 0, failed => 0, total_acls => 0, risky_acls => 0);

for my $device (@devices) {
    output("\n--- Device: $device ---");
    my $result = audit_device($device, $username, $password, $timeout);
    if ($result->{error}) {
        output("  FAILED: $result->{error}");
        $summary{failed}++;
    } else {
        $summary{processed}++;
        $summary{total_acls} += $result->{acl_count};
        $summary{risky_acls} += $result->{risky_count};
    }
}

output("\n" . "=" x 60);
output("SUMMARY");
output("  Devices successful : $summary{processed}");
output("  Devices failed     : $summary{failed}");
output("  Total ACLs found   : $summary{total_acls}");
output("  Risky ACLs (permit any): $summary{risky_acls}");
output("=" x 60);

close $log_fh if $log_fh;

sub audit_device {
    my ($dev, $user, $pass, $tout) = @_;
    my %result = (acl_count => 0, risky_count => 0);

    my $ssh = Net::SSH::Expect->new(
        host        => $dev,
        user        => $user,
        password    => $pass,
        timeout     => $tout,
        raw_pty     => 1,
    );

    eval {
        my $login = $ssh->login();
        if ($login !~ /[>#]/) {
            die "Authentication failed or unexpected prompt\n";
        }
        $ssh->send("terminal length 0\n");
        $ssh->waitfor('\s*[>#]', 10) or die "Timeout after terminal length\n";

        $ssh->send("show ip access-lists\n");
        my $output = '';
        while (1) {
            my $chunk = $ssh->waitfor('\s*[>#]', $tout);
            last unless defined $chunk;
            $output .= $chunk;
            last if $chunk =~ /[>#]\s*$/;
        }

        my %acls;
        my $current_acl = '';
        for my $line (split /\r?\n/, $output) {
            if ($line =~ /^(?:Standard|Extended)\s+IP\s+access\s+list\s+(\S+)/i) {
                $current_acl = $1;
                $acls{$current_acl} //= { entries => 0, risky => 0 };
            } elsif ($current_acl && $line =~ /^\s+\d+/) {
                $acls{$current_acl}{entries}++;
                if ($line =~ /permit\s+any\s+any/i || $line =~ /permit\s+any\s*$/i) {
                    $acls{$current_acl}{risky} = 1;
                }
            }
        }

        for my $acl_name (sort keys %acls) {
            my $flag = $acls{$acl_name}{risky} ? ' [RISK: permit any]' : '';
            output(sprintf("  %-30s  entries: %3d%s",
                $acl_name, $acls{$acl_name}{entries}, $flag));
            $result{acl_count}++;
            $result{risky_count}++ if $acls{$acl_name}{risky};
        }

        output("  No ACLs configured") unless %acls;
        $ssh->send("exit\n");
    };

    if ($@) {
        $result{error} = $@;
        $result{error} =~ s/\n/ /g;
        chomp $result{error};
    }

    return \%result;
}

sub output {
    my ($msg) = @_;
    print "$msg\n";
    if ($log_fh) {
        print $log_fh "$msg\n";
    }
}
```