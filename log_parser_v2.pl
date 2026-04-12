#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# syslog_security_audit.pl
#
# Purpose:
#   SSH into Cisco IOS/IOS-XE devices and parse buffered syslog for
#   security-relevant events: authentication failures, ACL denies,
#   port-security violations, and login anomalies.  Suitable for
#   scheduled auditing or incident triage.
#
# Usage:
#   perl syslog_security_audit.pl -h 192.0.2.1 -u admin -p secret
#   perl syslog_security_audit.pl --file devices.txt -u admin -p secret -o report.txt
#   perl syslog_security_audit.pl -h 192.0.2.1 -u admin -p secret --last 200
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to target device(s); 'logging buffered' must be enabled
#
# Output:
#   Prints flagged log lines to STDOUT (and optionally a file) grouped by
#   category: AUTH_FAIL, ACL_DENY, PORT_SEC, LOGIN_ANOMALY
# =============================================================================

my ($host, $user, $pass, $device_file, $out_file, $last_lines, $timeout);
$last_lines = 500;
$timeout    = 15;

GetOptions(
    'h|host=s'     => \$host,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'f|file=s'     => \$device_file,
    'o|output=s'   => \$out_file,
    'l|last=i'     => \$last_lines,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h <host> -u <user> -p <pass> [-f <file>] [-o <outfile>] [-l <lines>]\n";

die "Username required (-u)\n" unless $user;
die "Password required (-p)\n" unless $pass;
die "Provide -h <host> or -f <file>\n" unless $host || $device_file;

my @targets;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; push @targets, $_ if /\S/ && !/^#/; }
    close $fh;
} else {
    push @targets, $host;
}

my $out_fh;
if ($out_file) {
    open $out_fh, '>', $out_file or die "Cannot open $out_file for writing: $!\n";
}

my %patterns = (
    AUTH_FAIL    => qr/LOGIN_FAILED|Authentication failed|Bad passwords|%SEC_LOGIN-[45]-LOGIN_FAILED/i,
    ACL_DENY     => qr/%SEC-6-IPACCESSLOG|%SEC-6-IPACCESSLOGP|list \S+ denied/i,
    PORT_SEC     => qr/%PORT_SECURITY-2-PSECURE_VIOLATION|security violation/i,
    LOGIN_ANOMALY => qr/%SYS-5-CONFIG_I|%AAA-[345]-|%SSH-[34]-/i,
);

sub emit {
    my ($line) = @_;
    print $line;
    print $out_fh $line if $out_fh;
}

for my $target (@targets) {
    my $stamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
    emit("\n=== $target  [$stamp] ===\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $target,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    unless (eval { $ssh->login() }) {
        emit("  [ERROR] Connection/auth failed: $@\n");
        next;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('\$|#|>', 5);

    $ssh->send("show logging last $last_lines");
    my $raw = $ssh->waitfor('\$|#|>', $timeout) // '';

    $ssh->send('exit');
    $ssh->close();

    my %hits;
    for my $line (split /\n/, $raw) {
        for my $cat (keys %patterns) {
            if ($line =~ $patterns{$cat}) {
                push @{ $hits{$cat} }, $line;
                last;
            }
        }
    }

    if (!%hits) {
        emit("  No security events found in last $last_lines log lines.\n");
        next;
    }

    for my $cat (sort keys %hits) {
        emit(sprintf("  [%s] %d event(s):\n", $cat, scalar @{ $hits{$cat} }));
        for my $entry (@{ $hits{$cat} }) {
            $entry =~ s/^\s+|\s+$//g;
            emit("    $entry\n");
        }
    }
}

close $out_fh if $out_fh;
print "\nDone. Output saved to $out_file\n" if $out_file;