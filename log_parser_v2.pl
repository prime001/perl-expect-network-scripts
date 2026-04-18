#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

#
# security_log_audit.pl - Network Device Security Event Log Auditor
#
# PURPOSE:
#   Connects to Cisco IOS/IOS-XE devices and parses buffered syslog output
#   for security-relevant events: failed authentications, ACL denies,
#   configuration changes, and privilege escalations.
#
# USAGE:
#   perl security_log_audit.pl --host <IP> --user <username> --pass <password>
#   perl security_log_audit.pl --file devices.txt --user admin --pass secret --log audit.log
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#
# OUTPUT:
#   Categorized security events with timestamps, counts, and source IPs.
#   Exits with code 1 if critical thresholds are exceeded.
#

my ($host, $devfile, $username, $password, $logfile, $threshold);
$threshold = 5;

GetOptions(
    'host=s'      => \$host,
    'file=s'      => \$devfile,
    'user=s'      => \$username,
    'pass=s'      => \$password,
    'log=s'       => \$logfile,
    'threshold=i' => \$threshold,
) or die "Usage: $0 --host <ip> --user <u> --pass <p> [--log file] [--threshold N]\n";

die "Provide --host or --file\n" unless $host || $devfile;
die "Provide --user and --pass\n" unless $username && $password;

my @devices = $host ? ($host) : do {
    open my $fh, '<', $devfile or die "Cannot open $devfile: $!\n";
    map { chomp; $_ } grep { /\S/ && !/^#/ } <$fh>;
};

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log $logfile: $!\n";
}

sub log_print {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my $dev = shift;
    my $ts  = strftime('%Y-%m-%d %H:%M:%S', localtime);

    log_print("\n=== Security Log Audit: $dev  [$ts] ===\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $dev,
        user        => $username,
        password     => $password,
        raw_pty     => 1,
        timeout     => 20,
    );

    eval { $ssh->login() };
    if ($@) {
        log_print("  [ERROR] SSH login failed for $dev: $@\n");
        return;
    }

    $ssh->exec("terminal length 0");

    my $raw = $ssh->exec("show logging | include %SEC|%LOGIN|%AAA|%SYS-5-CONFIG|%PARSER|denied");
    $ssh->close();

    unless ($raw) {
        log_print("  [WARN]  No output received from $dev\n");
        return;
    }

    my (%events, @acl_denies, %fail_src);

    for my $line (split /\n/, $raw) {
        next unless $line =~ /^[*%]|^\d/;
        $line =~ s/\r//g;

        if ($line =~ /Login\s+failed|Authentication\s+failed|%LOGIN-\d-FAIL/i) {
            $events{auth_fail}++;
            $fail_src{$1}++ if $line =~ /from\s+(\d+\.\d+\.\d+\.\d+)/;
        }
        elsif ($line =~ /%SYS-5-CONFIG_I/i) {
            $events{config_change}++;
            my $who = ($line =~ /by\s+(\S+)\s+on/) ? $1 : 'unknown';
            log_print("  [CONFIG] Change by $who: $line\n");
        }
        elsif ($line =~ /denied|%SEC-6-IPACCESSLOG/i) {
            $events{acl_deny}++;
            push @acl_denies, $line if @acl_denies < 10;
        }
        elsif ($line =~ /%AAA-\d|privilege.*level/i) {
            $events{priv_change}++;
            log_print("  [PRIV]  $line\n");
        }
    }

    log_print("  Auth failures : " . ($events{auth_fail}   // 0) . "\n");
    log_print("  Config changes: " . ($events{config_change} // 0) . "\n");
    log_print("  ACL denies    : " . ($events{acl_deny}     // 0) . "\n");
    log_print("  Priv changes  : " . ($events{priv_change}  // 0) . "\n");

    if (%fail_src) {
        log_print("  Failed login sources:\n");
        for my $ip (sort { $fail_src{$b} <=> $fail_src{$a} } keys %fail_src) {
            log_print("    $ip : $fail_src{$ip} attempt(s)\n");
        }
    }

    if (@acl_denies) {
        log_print("  Recent ACL denies (up to 10):\n");
        log_print("    $_\n") for @acl_denies;
    }

    if (($events{auth_fail} // 0) >= $threshold) {
        log_print("  [ALERT] Auth failure threshold ($threshold) exceeded on $dev!\n");
        return 1;
    }
    return 0;
}

my $exit_code = 0;
for my $dev (@devices) {
    $exit_code |= audit_device($dev);
}

close $log_fh if $log_fh;
exit $exit_code;