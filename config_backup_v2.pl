Here is the script:

```
#!/usr/bin/perl
# startup_running_diff.pl - Detect unsaved configuration changes on Cisco IOS devices
#
# Purpose:
#   Connects to one or more network devices and compares running-config to
#   startup-config. Reports any device where changes exist but have not been
#   written to NVRAM. Useful for change audits, pre-maintenance checks, and
#   compliance enforcement ("no unsaved changes in prod").
#
# Usage:
#   Single device:  perl startup_running_diff.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    perl startup_running_diff.pl -f devices.txt -u admin -p secret
#   With log:       perl startup_running_diff.pl -f devices.txt -u admin -p secret -l diff_audit.log
#
# Device file format: one IP or hostname per line; lines starting with # are skipped.
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access enabled on target devices (ip ssh version 2)
#   Credentials with at least privilege 1 ("show" access)
#
# Exit codes: 0 = all devices clean, 1 = unsaved changes detected, 2 = script error

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file);
my $timeout = 15;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$log_file,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOGFILE] [-t TIMEOUT]\n";

die "Specify -h HOST or -f FILE\n"  unless $host || $device_file;
die "Username required (-u)\n"      unless $username;
die "Password required (-p)\n"      unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        s/^\s+|\s+$//g;
        next if /^#/ || /^$/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub log_print {
    my ($msg) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    my $line = "[$ts] $msg";
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}

my $has_diff   = 0;
my $error_count = 0;

log_print("Starting startup/running diff audit on " . scalar(@devices) . " device(s)");

for my $device (@devices) {
    my $ssh = Net::SSH::Expect->new(
        host        => $device,
        user        => $username,
        password     => $password,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    eval {
        my $login_output = $ssh->login();
        if ($login_output !~ /[>#]/) {
            die "Authentication failed or unexpected prompt\n";
        }

        $ssh->send("terminal length 0");
        $ssh->waitfor('[\$#>]', 5);

        $ssh->send("show archive config differences nvram:startup-config system:running-config");
        my $output = $ssh->waitfor('[\$#>]', $timeout);

        $ssh->send("exit");

        if (!defined $output || $output eq '') {
            log_print("WARN  $device: No output received");
            $error_count++;
            return;
        }

        # IOS returns "!Archiving configurations from this system" or
        # specific diff lines when changes exist; empty/no-diff returns
        # just the prompt. A clean device returns nothing between the
        # command and the next prompt.
        my @diff_lines = grep {
            /^[+\-!]/ && !/^---/ && !/^!!!/ && !/^!\s*$/ && !/Archiving/
        } split(/\n/, $output);

        if (@diff_lines) {
            $has_diff = 1;
            log_print("UNSAVED $device: " . scalar(@diff_lines) . " changed line(s) detected");
            for my $line (@diff_lines) {
                $line =~ s/^\s+|\s+$//g;
                next unless length($line);
                log_print("  $device >> $line");
            }
        } else {
            log_print("CLEAN   $device: startup matches running");
        }
    };

    if ($@) {
        my $err = $@;
        $err =~ s/\n/ /g;
        if ($err =~ /timeout/i) {
            log_print("ERROR  $device: Connection timed out");
        } elsif ($err =~ /auth|password|denied/i) {
            log_print("ERROR  $device: Authentication failed");
        } elsif ($err =~ /refused|no route|network/i) {
            log_print("ERROR  $device: Connection refused or unreachable");
        } else {
            log_print("ERROR  $device: $err");
        }
        $error_count++;
    }
}

log_print("Audit complete — devices checked: " . scalar(@devices) .
          ", unsaved changes: " . ($has_diff ? "YES" : "none") .
          ", errors: $error_count");

close $log_fh if $log_fh;

exit 2 if $error_count && !$has_diff;
exit 1 if $has_diff;
exit 0;
```

This is `startup_running_diff.pl` — detects unsaved config changes by running `show archive config differences` between NVRAM startup and the live running config. It's distinct from the existing config_backup scripts (which save configs) — this one audits for drift. Exit codes make it CI/cron-friendly: 0 clean, 1 unsaved changes found, 2 errors.