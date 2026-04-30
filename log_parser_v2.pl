The user has provided a complete, fully-specified request with explicit output format requirements ("Output ONLY the script content"). This is a concrete code generation task with no design ambiguity — the brainstorming skill is not applicable here.

Writing the security event log auditor script now.

#!/usr/bin/perl
#
# security_log_audit.pl — Live Security Event Auditor for IOS/IOS-XE Devices
#
# Purpose:
#   SSH into one or more Cisco IOS/IOS-XE devices, extract syslog entries
#   for security-relevant events (auth failures, ACL denies, privilege
#   escalation, SSH anomalies), and produce a structured per-device summary.
#   Distinct from generic log_parser scripts — focuses entirely on live
#   security triage across a device list.
#
# Usage:
#   ./security_log_audit.pl -h <host> [-u user] [-p pass] [-o logfile]
#   ./security_log_audit.pl -f <hostfile> [-u user] [-p pass] [-o logfile]
#
# Prerequisites:
#   cpanm Net::SSH::Expect Getopt::Long
#
# Environment:
#   NET_USER — SSH username (overridden by -u)
#   NET_PASS — SSH password (overridden by -p)
#
# Examples:
#   ./security_log_audit.pl -h 10.1.1.1 -u admin -o /tmp/audit.log
#   ./security_log_audit.pl -f routers.txt -u netops -o daily_sec.log

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log, $opt_timeout);
GetOptions(
    'h|host=s'    => \$opt_host,
    'f|file=s'    => \$opt_file,
    'u|user=s'    => \$opt_user,
    'p|pass=s'    => \$opt_pass,
    'o|output=s'  => \$opt_log,
    't|timeout=i' => \$opt_timeout,
) or die "Usage: $0 -h <host>|-f <file> [-u user] [-p pass] [-o logfile] [-t timeout]\n";

die "ERROR: Specify -h <host> or -f <hostfile>\n" unless $opt_host || $opt_file;

my $user    = $opt_user    || $ENV{NET_USER} || 'admin';
my $pass    = $opt_pass    || $ENV{NET_PASS} || die "ERROR: Password required via -p or NET_PASS env\n";
my $timeout = $opt_timeout || 30;

my @hosts;
if ($opt_host) {
    push @hosts, $opt_host;
} else {
    open my $fh, '<', $opt_file or die "ERROR: Cannot open $opt_file: $!\n";
    @hosts = map { chomp; $_ } grep { /\S/ && !/^\s*#/ } <$fh>;
    close $fh;
}
die "ERROR: No hosts found\n" unless @hosts;

my $LOG;
if ($opt_log) {
    open $LOG, '>>', $opt_log or die "ERROR: Cannot open $opt_log: $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $LOG $msg if $LOG;
}

my %checks = (
    'Auth Failures'      => 'LOGIN_FAILED|Bad passwords|Authentication failed|Invalid password',
    'ACL Deny Hits'      => '%SEC-6-IPACCESSLOG|%SEC-6-IPACCESSLOGP|%SEC-6-IPACCESSLOGDP',
    'Privilege Changes'  => 'SYS-5-CONFIG_I|PRIV_AUTH_PASS|PRIV_AUTH_FAIL|AAA-5-NOMETHLIST',
    'SSH Anomalies'      => '%SSH-3-|%SSH-4-|SSH2 0|sshd: error',
);

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=" x 62 . "\n");
out("Security Log Audit — $ts\n");
out("=" x 62 . "\n");

for my $device (@hosts) {
    out("\n[+] $device\n");
    out("-" x 40 . "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $device,
            user     => $user,
            password => $pass,
            raw_pty  => 1,
            timeout  => $timeout,
        );
    };
    if ($@ || !$ssh) {
        out("    ERROR: Cannot create SSH session — $@\n");
        next;
    }

    my $login_out = eval { $ssh->login() };
    if ($@ || !defined $login_out) {
        out("    ERROR: Authentication failed or connection refused\n");
        next;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|#|>', 5);

    for my $category (sort keys %checks) {
        my $pattern = $checks{$category};
        my $cmd     = "show logging | include $pattern";
        my $raw     = eval { $ssh->exec($cmd) } // '';
        my @hits    = grep { /\%\w|\bfail|\berror/i }
                      grep { !/^[A-Za-z0-9_\-]+[#>]|^show logging/ }
                      split(/\r?\n/, $raw);
        my $count   = scalar @hits;
        out("    $category: $count event(s)\n");
        if ($count > 0) {
            my $show  = $count > 5 ? 5 : $count;
            out("      $_\n") for @hits[0 .. $show - 1];
            out("      ... (${\($count - $show)} more)\n") if $count > $show;
        }
    }

    eval { $ssh->send("exit\n") };
}

out("\n" . "=" x 62 . "\n");
out("Audit complete — " . scalar(@hosts) . " device(s) checked\n");
out("=" x 62 . "\n");
close $LOG if $LOG;