```perl
#!/usr/bin/perl
#
# unsaved_changes_check.pl - Detect unsaved running/startup config differences
#
# PURPOSE:
#   Connects to Cisco IOS/IOS-XE devices and checks for unsaved configuration
#   changes by comparing running-config against startup-config. Useful for
#   compliance audits and pre-maintenance validation to ensure all changes
#   have been written to NVRAM.
#
# USAGE:
#   Single device:  ./unsaved_changes_check.pl -h 192.168.1.1
#   Device file:    ./unsaved_changes_check.pl -f devices.txt
#   With logging:   ./unsaved_changes_check.pl -f devices.txt -l check.log
#   Custom creds:   ./unsaved_changes_check.pl -h 10.0.0.1 -u admin -p secret -e enable
#
# DEVICE FILE FORMAT:
#   One IP or hostname per line; lines starting with # are ignored.
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   SSH access to devices with credentials that have 'show' privilege
#   Devices must support: show archive config differences

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $log_file, $username, $password, $enable_pass);
my $timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'l|log=s'      => \$log_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'e|enable=s'   => \$enable_pass,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> [-l logfile] [-u user] [-p pass] [-e enable]\n";

die "Specify -h <host> or -f <file>\n" unless $host || $device_file;

$username    ||= $ENV{NET_USER}   || 'admin';
$password    ||= $ENV{NET_PASS}   || die "Password required: use -p or set NET_PASS\n";
$enable_pass ||= $ENV{NET_ENABLE} || $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
    die "No devices found in $device_file\n" unless @devices;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>', $log_file) or die "Cannot open log $log_file: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
log_output("=" x 60);
log_output("Unsaved Config Check  |  $timestamp");
log_output("=" x 60);

my (%saved, %unsaved, %failed);

for my $device (@devices) {
    log_output("\n[$device] Connecting...");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $device,
            user        => $username,
            password     => $password,
            raw_pty     => 1,
            timeout     => $timeout,
        );
    };
    if ($@ || !$ssh) {
        log_output("[$device] ERROR: Failed to create SSH session: $@");
        $failed{$device} = "connection error";
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        log_output("[$device] ERROR: Login failed (check credentials)");
        $failed{$device} = "auth failure";
        next;
    }

    # Enter enable mode if prompt shows '>'
    if ($login =~ />/) {
        $ssh->send("enable");
        $ssh->waitfor('Password.*:', 5);
        $ssh->send($enable_pass);
        $ssh->waitfor('#', 10) or do {
            log_output("[$device] ERROR: Enable mode failed");
            $failed{$device} = "enable failed";
            $ssh->close();
            next;
        };
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('#', 5);

    $ssh->send("show archive config differences");
    my $output = $ssh->waitfor('#', $timeout);

    if (!defined $output) {
        log_output("[$device] WARN: No response to diff command (may not support archive config)");
        $failed{$device} = "command unsupported";
        $ssh->close();
        next;
    }

    $ssh->send("exit");
    $ssh->close();

    # If output contains only the prompt/command echo, configs match
    my $has_diff = ($output =~ /^[+\-]/m || $output =~ /Current\s+Configuration/m);

    if ($has_diff) {
        log_output("[$device] *** UNSAVED CHANGES DETECTED ***");
        $unsaved{$device} = $output;
    } else {
        log_output("[$device] OK - Running config matches startup");
        $saved{$device} = 1;
    }
}

log_output("\n" . "=" x 60);
log_output("SUMMARY");
log_output("=" x 60);
log_output(sprintf("  Clean (saved):    %d", scalar keys %saved));
log_output(sprintf("  Unsaved changes:  %d", scalar keys %unsaved));
log_output(sprintf("  Failed/errors:    %d", scalar keys %failed));

if (%unsaved) {
    log_output("\nDevices with unsaved changes:");
    log_output("  $_") for sort keys %unsaved;
}
if (%failed) {
    log_output("\nDevices with errors:");
    log_output("  $_ ($failed{$_})") for sort keys %failed;
}

close $log_fh if $log_fh;
exit(scalar keys %unsaved > 0 ? 1 : 0);

sub log_output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}
```