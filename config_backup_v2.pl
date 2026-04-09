```perl
#!/usr/bin/perl
# =============================================================================
# running_vs_startup.pl - Unsaved Config Change Detector
# =============================================================================
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE devices and compares the running
#   configuration against the startup configuration. Flags any device where
#   changes have been made but not saved with 'write memory'. Useful for
#   compliance checks, change window audits, and pre-maintenance validation.
#
# Usage:
#   Single device:   ./running_vs_startup.pl -h 192.168.1.1
#   Device file:     ./running_vs_startup.pl -f devices.txt
#   With logging:    ./running_vs_startup.pl -f devices.txt -l audit.log
#   Custom creds:    ./running_vs_startup.pl -h 10.0.0.1 -u admin -p secret
#
# Device file format (one IP or hostname per line, # for comments):
#   192.168.1.1
#   192.168.1.2
#   # core-switch.example.com
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH key-based auth recommended; password auth supported via -p flag
#   Devices must allow 'show archive config differences' or fallback method
#
# Exit codes:
#   0 = All devices in sync (running == startup)
#   1 = One or more devices have unsaved changes
#   2 = Script error (bad args, unreadable file, etc.)
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $log_file, $username, $password, $help);
my $timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'l|log=s'      => \$log_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    't|timeout=i'  => \$timeout,
    'help'         => \$help,
) or die "Error parsing arguments. Use --help for usage.\n";

if ($help) {
    system("grep '^#' $0 | head -30 | sed 's/^# //; s/^#//'");
    exit 0;
}

unless ($host || $device_file) {
    print STDERR "Error: specify -h <host> or -f <device_file>\n";
    exit 2;
}

$username //= $ENV{NET_USER} // 'admin';
$password //= $ENV{NET_PASS} // '';

my @devices;
if ($host) {
    push @devices, $host;
}
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        s/\s+$//;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log $log_file: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $header = "=" x 60 . "\nUnsaved Config Audit - $timestamp\n" . "=" x 60;
output($header);

my $overall_exit = 0;

for my $device (@devices) {
    output("\n[$device] Connecting...");

    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $username,
        password    => $password,
        raw_pty     => 1,
        timeout     => $timeout,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    my $login_output;
    eval {
        $login_output = $ssh->login();
    };
    if ($@ || !defined $login_output) {
        output("[$device] FAIL: Connection error - $@");
        $overall_exit = 1;
        next;
    }
    if ($login_output =~ /Permission denied|Authentication failed/i) {
        output("[$device] FAIL: Authentication failed");
        $overall_exit = 1;
        next;
    }

    # Disable paging
    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|#', 5);

    # Try 'show archive config differences' first (IOS 12.3+)
    $ssh->send("show archive config differences\n");
    my $diff_output = $ssh->waitfor('\$|#', $timeout);

    if (!defined $diff_output) {
        output("[$device] WARN: Timeout waiting for diff output");
        $overall_exit = 1;
        $ssh->close();
        next;
    }

    # Fallback: check if archive is configured; if not, use show running vs startup checksum approach
    my $has_unsaved = 0;
    my $method_used = 'archive';

    if ($diff_output =~ /not configured|invalid input|error/i) {
        # Fallback: compare MD5 of running vs startup isn't native; instead check 'show startup-config'
        # to see if it's absent or compare modification time via 'show version' build info
        $ssh->send("show startup-config | include Last configuration\n");
        my $startup_info = $ssh->waitfor('\$|#', 15);
        $ssh->send("show running-config | include Last configuration\n");
        my $running_info = $ssh->waitfor('\$|#', 15);
        $method_used = 'timestamp';

        # Simple heuristic: if no startup config exists, device is definitely out of sync
        if (!defined $startup_info || $startup_info =~ /startup.*not.*present|nvram.*not.*configured/i) {
            $has_unsaved = 1;
        } else {
            # Cannot definitively compare without archive; report as unknown
            output("[$device] INFO: 'archive' not configured - cannot perform diff. Enable 'archive' for full support.");
            $ssh->close();
            next;
        }
    } elsif ($diff_output =~ /no changes|identical|Contextual Config Diffs:\s*\n\s*\n/si) {
        $has_unsaved = 0;
    } elsif ($diff_output =~ /^\+|^-/m) {
        $has_unsaved = 1;
    }

    if ($has_unsaved) {
        output("[$device] *** UNSAVED CHANGES DETECTED (method: $method_used) ***");
        if ($method_used eq 'archive' && $diff_output =~ /((?:^[+-].*\n)+)/m) {
            my $changes = $1;
            $changes =~ s/^/  /mg;
            output("[$device] Changed lines:\n$changes");
        }
        $overall_exit = 1;
    } else {
        output("[$device] OK: running-config matches startup-config");
    }

    $ssh->send("exit\n");
    $ssh->close();
}

output("\n" . "=" x 60);
output($overall_exit ? "RESULT: Unsaved changes found on one or more devices" : "RESULT: All devices in sync");
output("=" x 60);

close $log_fh if $log_fh;
exit $overall_exit;

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}
```