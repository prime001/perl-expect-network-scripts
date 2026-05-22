```perl
#!/usr/bin/perl
# =============================================================================
# ntp_compliance_audit.pl - NTP Server Compliance Auditor
#
# Purpose:
#   Audits network devices to verify NTP configuration against an approved
#   server whitelist. Checks for unauthorized NTP sources, verifies
#   authentication is enabled, and flags stratum-1 references (potential
#   misconfiguration). Essential for PCI-DSS / SOC2 time-source compliance.
#
# Usage:
#   ./ntp_compliance_audit.pl -h 192.168.1.1 [-u admin] [-p password]
#   ./ntp_compliance_audit.pl -f device_list.txt [-u admin] [-p password]
#   ./ntp_compliance_audit.pl -h 10.0.0.1 -w whitelist.txt -l audit.log
#
# Options:
#   -h <host>        Single device IP or hostname
#   -f <file>        File containing one device IP per line
#   -u <user>        SSH username (default: admin)
#   -p <password>    SSH password (prompts if omitted)
#   -w <whitelist>   File with approved NTP server IPs, one per line
#   -l <logfile>     Output log file (default: ntp_audit_YYYYMMDD.log)
#   -t <timeout>     SSH timeout in seconds (default: 15)
#
# Prerequisites:
#   cpan Net::SSH::Expect Term::ReadKey
#   Tested against Cisco IOS/IOS-XE. Adapts to NX-OS with minor changes.
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);
use Term::ReadKey;

my %opts;
getopts('h:f:u:p:w:l:t:', \%opts);

my $username  = $opts{u} || 'admin';
my $timeout   = $opts{t} || 15;
my $timestamp = strftime('%Y%m%d_%H%M%S', localtime);
my $logfile   = $opts{l} || "ntp_audit_${timestamp}.log";

unless ($opts{h} || $opts{f}) {
    die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-w whitelist] [-l logfile]\n";
}

my $password = $opts{p};
unless ($password) {
    print "SSH Password: ";
    ReadMode('noecho');
    chomp($password = <STDIN>);
    ReadMode('restore');
    print "\n";
}

my %whitelist;
if ($opts{w} && -f $opts{w}) {
    open my $wfh, '<', $opts{w} or die "Cannot open whitelist $opts{w}: $!";
    while (<$wfh>) {
        chomp;
        s/\s+//g;
        $whitelist{$_} = 1 if $_;
    }
    close $wfh;
}

my @devices;
if ($opts{h}) {
    push @devices, $opts{h};
} elsif ($opts{f}) {
    open my $fh, '<', $opts{f} or die "Cannot open device file $opts{f}: $!";
    while (<$fh>) { chomp; push @devices, $_ if /\S/; }
    close $fh;
}

open my $log, '>', $logfile or die "Cannot open log $logfile: $!";

sub output {
    my $msg = shift;
    print $msg;
    print $log $msg;
}

output("NTP Compliance Audit - $timestamp\n");
output("=" x 60 . "\n");
output(sprintf("Whitelist: %s\n", scalar(keys %whitelist) ? "$opts{w} (" . scalar(keys %whitelist) . " entries)" : "none (report-only mode)"));
output("Devices: " . scalar(@devices) . "\n\n");

my ($pass_count, $fail_count, $error_count) = (0, 0, 0);

for my $host (@devices) {
    output("Device: $host\n");
    output("-" x 40 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $username,
        password    => $password,
        timeout     => $timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        output("  ERROR: Connection failed - $@\n\n");
        $error_count++;
        next;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|#|>', 5);

    $ssh->send("show ntp associations\n");
    my $assoc_output = $ssh->waitfor('\$|#|>', $timeout) // '';

    $ssh->send("show ntp status\n");
    my $status_output = $ssh->waitfor('\$|#|>', $timeout) // '';

    $ssh->send("show run | include ntp\n");
    my $config_output = $ssh->waitfor('\$|#|>', $timeout) // '';

    $ssh->close();

    my @configured_servers;
    while ($config_output =~ /ntp\s+server\s+(\S+)/gi) {
        push @configured_servers, $1;
    }

    my $auth_enabled = ($config_output =~ /ntp\s+authenticate/i) ? 'YES' : 'NO';
    my $synced       = ($status_output =~ /Clock is synchronized/i) ? 'YES' : 'NO';

    my ($stratum) = ($status_output =~ /stratum\s+(\d+)/i);
    $stratum //= 'unknown';

    output("  Sync Status  : $synced\n");
    output("  Stratum      : $stratum\n");
    output("  Auth Enabled : $auth_enabled\n");
    output("  Configured Servers:\n");

    my $device_compliant = 1;
    for my $srv (@configured_servers) {
        my $status = '';
        if (%whitelist) {
            $status = $whitelist{$srv} ? '[APPROVED]' : '[UNAUTHORIZED]';
            $device_compliant = 0 unless $whitelist{$srv};
        }
        output("    $srv $status\n");
    }
    output("    (none configured)\n") unless @configured_servers;

    if ($stratum eq '1') {
        output("  WARNING: Device references a stratum-1 source directly\n");
        $device_compliant = 0;
    }
    if ($auth_enabled eq 'NO') {
        output("  WARNING: NTP authentication not enabled\n");
        $device_compliant = 0 if %whitelist;
    }

    if (%whitelist) {
        my $verdict = $device_compliant ? 'PASS' : 'FAIL';
        output("  Compliance   : $verdict\n");
        $device_compliant ? $pass_count++ : $fail_count++;
    }
    output("\n");
}

output("=" x 60 . "\n");
output("Summary: " . scalar(@devices) . " devices | ");
if (%whitelist) {
    output("PASS=$pass_count FAIL=$fail_count ERROR=$error_count\n");
} else {
    output("ERROR=$error_count (report-only, no whitelist provided)\n");
}
output("Log: $logfile\n");

close $log;
exit($fail_count > 0 ? 1 : 0);
```