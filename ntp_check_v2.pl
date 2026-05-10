#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# ntp_compliance_audit.pl
#
# Purpose:
#   Audits NTP security and policy compliance on Cisco IOS/IOS-XE devices.
#   Checks authentication keys, ACL enforcement, approved server list adherence,
#   and stratum policy -- NOT just sync status. Use ntp_check.pl for basic
#   operational status; use this when you need to verify NTP config meets policy.
#
# Usage:
#   ntp_compliance_audit.pl -h 192.168.1.1 -u admin -p secret [options]
#   ntp_compliance_audit.pl -f devices.txt -u admin -p secret [options]
#
# Options:
#   -h, --host      Single device IP or hostname
#   -f, --file      File with one device per line
#   -u, --user      SSH username
#   -p, --pass      SSH password
#   -s, --servers   Comma-separated approved NTP server IPs
#   -m, --maxstrat  Maximum allowed stratum (default: 4)
#   -l, --log       Log file path (optional)
#   -t, --timeout   SSH timeout in seconds (default: 15)
#
# Prerequisites:
#   Net::SSH::Expect (cpan install Net::SSH::Expect)
#   SSH enabled on target devices, valid credentials

my ($host, $file, $user, $pass, $servers_arg, $log_file);
my $max_stratum = 4;
my $timeout     = 15;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$file,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    's|servers=s'  => \$servers_arg,
    'm|maxstrat=i' => \$max_stratum,
    'l|log=s'      => \$log_file,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [options]\n";

die "Must specify -h or -f\n"    unless $host || $file;
die "Must specify -u username\n" unless $user;
die "Must specify -p password\n" unless $pass;

my @approved_servers = $servers_arg ? split(/,/, $servers_arg) : ();
my @devices = $host ? ($host) : do {
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    map { chomp; $_ } grep { /\S/ && !/^#/ } <$fh>;
};

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub log_out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub audit_device {
    my ($dev) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    log_out("\n[$ts] Auditing $dev\n" . "-" x 60 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $dev,
        user        => $user,
        password     => $pass,
        raw_pty      => 1,
        timeout      => $timeout,
    );

    eval { $ssh->login() };
    if ($@) {
        log_out("  FAIL: Cannot connect to $dev: $@\n");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('>#', 3);

    my %findings;

    # Check NTP authentication
    $ssh->send("show run | section ntp");
    my $ntp_config = $ssh->waitfor('>#', 10) // '';

    $findings{auth_enabled}  = $ntp_config =~ /ntp authenticate\b/ ? 1 : 0;
    $findings{auth_keys}     = () = $ntp_config =~ /ntp authentication-key/g;
    $findings{trusted_keys}  = () = $ntp_config =~ /ntp trusted-key/g;
    $findings{acl_applied}   = $ntp_config =~ /ntp access-group/ ? 1 : 0;
    $findings{source_iface}  = $ntp_config =~ /ntp source\s+(\S+)/ ? $1 : 'none';

    my @configured_servers = ($ntp_config =~ /ntp server\s+([\d\.]+)/g);
    $findings{server_count}  = scalar @configured_servers;

    # Check for rogue servers if approved list provided
    my @rogue;
    if (@approved_servers) {
        my %approved = map { $_ => 1 } @approved_servers;
        @rogue = grep { !$approved{$_} } @configured_servers;
    }
    $findings{rogue_servers} = \@rogue;

    # Check stratum from operational state
    $ssh->send("show ntp status");
    my $ntp_status = $ssh->waitfor('>#', 10) // '';
    my ($stratum) = $ntp_status =~ /stratum\s+(\d+)/i;
    $findings{stratum}      = $stratum // 'unknown';
    $findings{synchronized} = $ntp_status =~ /Clock is synchronized/i ? 1 : 0;

    $ssh->send("exit");
    $ssh->close();

    # Report
    my $pass_fail = sub { $_[0] ? "PASS" : "FAIL" };

    log_out(sprintf("  NTP Synchronized  : %s\n", $findings{synchronized} ? "YES" : "NO"));
    log_out(sprintf("  Stratum           : %s  [%s]\n",
        $findings{stratum},
        ($findings{stratum} eq 'unknown' || $findings{stratum} > $max_stratum) ? "FAIL" : "PASS"));
    log_out(sprintf("  Authentication    : %s\n", &$pass_fail($findings{auth_enabled})));
    log_out(sprintf("  Auth Keys         : %d configured, %d trusted\n",
        $findings{auth_keys}, $findings{trusted_keys}));
    log_out(sprintf("  ACL Enforced      : %s\n", &$pass_fail($findings{acl_applied})));
    log_out(sprintf("  Source Interface  : %s\n", $findings{source_iface}));
    log_out(sprintf("  NTP Servers       : %s\n", join(', ', @configured_servers) || 'none'));

    if (@approved_servers && @{$findings{rogue_servers}}) {
        log_out(sprintf("  ROGUE SERVERS     : FAIL -- %s\n",
            join(', ', @{$findings{rogue_servers}})));
    } elsif (@approved_servers) {
        log_out("  Approved Servers  : PASS\n");
    }

    my $compliant = $findings{auth_enabled}
        && $findings{trusted_keys}
        && $findings{acl_applied}
        && $findings{synchronized}
        && ($findings{stratum} ne 'unknown' && $findings{stratum} <= $max_stratum)
        && !@{$findings{rogue_servers}};

    log_out(sprintf("\n  COMPLIANCE STATUS : %s\n", $compliant ? "COMPLIANT" : "NON-COMPLIANT"));
}

log_out("NTP Compliance Audit -- " . strftime('%Y-%m-%d %H:%M:%S', localtime) . "\n");
log_out("Approved servers: " . (@approved_servers ? join(', ', @approved_servers) : 'not enforced') . "\n");
log_out("Max stratum: $max_stratum\n");

audit_device($_) for @devices;

log_out("\nAudit complete. " . scalar(@devices) . " device(s) checked.\n");
close $log_fh if $log_fh;