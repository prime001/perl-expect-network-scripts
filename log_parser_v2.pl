```perl
#!/usr/bin/perl
#
# security_log_analyzer.pl - Cisco IOS Security Event Log Analyzer
#
# Purpose:
#   SSHes into one or more Cisco IOS devices, retrieves the buffered syslog
#   via 'show logging', and categorizes security-relevant events: ACL deny
#   hits, authentication failures, port-security violations, err-disabled
#   ports, and STP topology changes. Produces a prioritized report suitable
#   for daily NOC triage or incident response.
#
# Usage:
#   ./security_log_analyzer.pl <device_ip> [username] [password]
#   ./security_log_analyzer.pl --file devices.txt [--user admin] [--pass s3cr3t]
#   ./security_log_analyzer.pl --file devices.txt --logdir /var/log/netaudit
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   IOS 'logging buffered' must be configured on target devices
#   NET_USER / NET_PASS env vars can substitute for --user / --pass
#
# Output:
#   STDOUT: categorized event summary per device
#   File:   security_events_<device>_<timestamp>.log  (in --logdir, default '.')
#

use strict;
use warnings;
use Net::SSH::Expect;
use POSIX        qw(strftime);
use Getopt::Long qw(GetOptions);

my $timeout  = 15;
my $log_dir  = '.';
my $username = $ENV{NET_USER} // 'admin';
my $password = $ENV{NET_PASS} // '';
my $file;

GetOptions(
    'file=s'    => \$file,
    'user=s'    => \$username,
    'pass=s'    => \$password,
    'logdir=s'  => \$log_dir,
    'timeout=i' => \$timeout,
) or die "Invalid options. See header for usage.\n";

my @devices;
if ($file) {
    open my $fh, '<', $file or die "Cannot open device file '$file': $!\n";
    while (<$fh>) {
        chomp;
        s/#.*//; s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
} elsif (@ARGV) {
    push @devices, shift @ARGV;
    $username = shift @ARGV if @ARGV;
    $password = shift @ARGV if @ARGV;
} else {
    die "Usage: $0 <device_ip> [user] [pass]\n       $0 --file devices.txt\n";
}

die "No devices specified.\n" unless @devices;

my %patterns = (
    auth_fail   => qr/\%(?:SEC|AAA|LOGIN)-\d+-(?:AUTHFAIL|BADAUTH|LOGIN_FAILED|IPACCESSLOGP?):/i,
    port_sec    => qr/\%PORT_SECURITY-\d+-PSECURE_VIOLATION:/i,
    err_disable => qr/\%PM-\d+-ERR_DISABLE:/i,
    acl_deny    => qr/\%SEC-\d+-IPACCESSLOG(?:P|DP|SP)?:.*denied/i,
    stp_change  => qr/\%SPANTREE-\d+-(?:TOPOLOGY_CHANGE|BLOCK_BPDUGUARD|ROOTGUARD_CONFIG_CHANGE):/i,
);

my %labels = (
    auth_fail   => 'Authentication Failures',
    port_sec    => 'Port Security Violations',
    err_disable => 'Err-Disabled Ports',
    acl_deny    => 'ACL Deny Hits',
    stp_change  => 'STP Events',
);

my $stamp = strftime('%Y%m%d_%H%M%S', localtime);

for my $device (@devices) {
    print "\n" . ('=' x 70) . "\n";
    print "Device: $device\n";
    print ('=' x 70) . "\n";
    analyze_device($device);
}

sub analyze_device {
    my ($host) = @_;

    my $ssh = Net::SSH::Expect->new(
        host       => $host,
        user       => $username,
        password   => $password,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        timeout    => $timeout,
        raw_pty    => 1,
    );

    unless (eval { $ssh->login() }) {
        warn "  [CONNECT ERROR] $host: " . ($@ || 'login failed') . "\n";
        return;
    }

    $ssh->exec("terminal length 0");
    my $output = $ssh->exec("show logging");
    $ssh->close();

    unless (defined $output && $output =~ /\S/) {
        warn "  [ERROR] Empty response from 'show logging' on $host\n";
        return;
    }

    my %events;
    $events{$_} = [] for keys %patterns;

    for my $line (split /\n/, $output) {
        $line =~ s/\r//g;
        next unless $line =~ /^\S/;
        for my $cat (keys %patterns) {
            push @{ $events{$cat} }, $line if $line =~ $patterns{$cat};
        }
    }

    my $total = 0;
    $total += @{ $events{$_} } for keys %events;

    my $log_path = "$log_dir/security_events_${host}_${stamp}.log";
    open my $log, '>', $log_path or do {
        warn "  [WARN] Cannot write log file '$log_path': $!\n";
        undef $log;
    };

    my $report_time = strftime('%Y-%m-%d %H:%M:%S', localtime);
    _out($log, "Report Time : $report_time\n");
    _out($log, "Total Events: $total\n");
    _out($log, ('-' x 70) . "\n");

    if ($total == 0) {
        _out($log, "No security events found in logging buffer.\n");
    } else {
        for my $cat (qw(auth_fail port_sec err_disable acl_deny stp_change)) {
            my @hits = @{ $events{$cat} };
            next unless @hits;
            _out($log, sprintf("\n[%s] — %d event%s\n", $labels{$cat}, scalar @hits, @hits == 1 ? '' : 's'));
            _out($log, "  $_\n") for @hits;
        }
    }

    close $log if $log;
    print "  Log: $log_path\n" if $log && -f $log_path;
}

sub _out {
    my ($fh, $msg) = @_;
    print $msg;
    print $fh $msg if $fh;
}
```