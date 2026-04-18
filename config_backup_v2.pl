It looks like write access to that path isn't granted. Here's the complete script — you can save it wherever you need:

```perl
#!/usr/bin/perl
# =============================================================================
# config_diff.pl - Running vs Startup Configuration Diff Checker
# =============================================================================
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE devices and checks whether the
#   running configuration differs from the startup configuration.  Any device
#   with unsaved changes is flagged so engineers can decide to "write mem"
#   before a maintenance window or power cycle.
#
# Usage:
#   Single device:  perl config_diff.pl -h 192.168.1.1 [-u admin] [-p secret]
#   Device file:    perl config_diff.pl -f devices.txt  [-u admin] [-p secret]
#   With log file:  perl config_diff.pl -f devices.txt  -l diff_report.log
#
#   devices.txt contains one IP/hostname per line; lines starting with # are
#   treated as comments and skipped.
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to devices with 'show archive config differences' support
#   (IOS 12.3(7)T+ / IOS-XE).  Falls back to comparing line counts if the
#   archive command is unsupported.
#
# Exit codes:
#   0 = all devices in sync
#   1 = one or more devices have unsaved changes or connection errors
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------
my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log);
$opt_user = 'admin';

GetOptions(
    'h|host=s'     => \$opt_host,
    'f|file=s'     => \$opt_file,
    'u|user=s'     => \$opt_user,
    'p|password=s' => \$opt_pass,
    'l|log=s'      => \$opt_log,
) or die "Usage: $0 -h HOST | -f FILE [-u user] [-p pass] [-l logfile]\n";

die "Specify -h HOST or -f FILE\n" unless $opt_host || $opt_file;

if (!$opt_pass) {
    print "Password: ";
    system('stty', '-echo');
    chomp($opt_pass = <STDIN>);
    system('stty', 'echo');
    print "\n";
}

# ---------------------------------------------------------------------------
# Build device list
# ---------------------------------------------------------------------------
my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open my $fh, '<', $opt_file or die "Cannot open $opt_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^\s*#/;
        push @devices, $_;
    }
    close $fh;
    die "No devices found in $opt_file\n" unless @devices;
}

# ---------------------------------------------------------------------------
# Logging helper
# ---------------------------------------------------------------------------
my $log_fh;
if ($opt_log) {
    open $log_fh, '>', $opt_log or die "Cannot open log $opt_log: $!\n";
}

sub log_msg {
    my ($msg) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    my $line = "[$ts] $msg";
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}

# ---------------------------------------------------------------------------
# Per-device check
# ---------------------------------------------------------------------------
sub check_device {
    my ($host) = @_;
    log_msg("Connecting to $host ...");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $opt_user,
        password    => $opt_pass,
        raw_pty     => 1,
        timeout     => 20,
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@ || !defined $login_output) {
        log_msg("ERROR [$host]: Connection/auth failed - $@");
        return 'error';
    }
    if ($login_output =~ /Permission denied|Access denied/i) {
        log_msg("ERROR [$host]: Authentication rejected");
        $ssh->close();
        return 'error';
    }

    # Disable paging
    $ssh->send('terminal length 0');
    $ssh->waitfor('\#', 5);

    # Try the archive diff command first (most reliable)
    $ssh->send('show archive config differences');
    my $diff_out = $ssh->waitfor('\#', 30);

    my $status;
    if ($diff_out && $diff_out !~ /Invalid|error|not enabled/i) {
        # Archive command succeeded — any output beyond header = unsaved changes
        my @diff_lines = grep { !/^$host|^\s*$|^!/ } split /\n/, $diff_out;
        if (@diff_lines) {
            log_msg("UNSAVED [$host]: Running config differs from startup (${\scalar @diff_lines} changed line(s))");
            $status = 'dirty';
        } else {
            log_msg("IN-SYNC [$host]: Running and startup configs match");
            $status = 'clean';
        }
    } else {
        # Fallback: compare line counts of running vs startup
        $ssh->send('show running-config | count ^');
        my $run_raw = $ssh->waitfor('\#', 30);
        $ssh->send('show startup-config | count ^');
        my $start_raw = $ssh->waitfor('\#', 30);

        my ($run_count)   = ($run_raw   =~ /Number of lines.*?:\s*(\d+)/i);
        my ($start_count) = ($start_raw =~ /Number of lines.*?:\s*(\d+)/i);

        if (defined $run_count && defined $start_count) {
            if ($run_count != $start_count) {
                log_msg("UNSAVED [$host]: Line count mismatch (running=$run_count startup=$start_count)");
                $status = 'dirty';
            } else {
                log_msg("IN-SYNC [$host]: Line counts match ($run_count lines) — consider enabling archive for full diff");
                $status = 'clean';
            }
        } else {
            log_msg("UNKNOWN [$host]: Could not determine config state");
            $status = 'unknown';
        }
    }

    $ssh->send('exit');
    $ssh->close();
    return $status;
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
my %results;
log_msg("Starting config diff check on ${\scalar @devices} device(s)");
log_msg('-' x 60);

for my $host (@devices) {
    $results{$host} = check_device($host);
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_msg('=' x 60);
log_msg('SUMMARY');
log_msg('=' x 60);

my @dirty   = grep { $results{$_} eq 'dirty'   } keys %results;
my @clean   = grep { $results{$_} eq 'clean'   } keys %results;
my @errors  = grep { $results{$_} eq 'error'   } keys %results;
my @unknown = grep { $results{$_} eq 'unknown' } keys %results;

log_msg("In sync:         " . scalar @clean);
log_msg("Unsaved changes: " . scalar @dirty);
log_msg("Errors:          " . scalar @errors);
log_msg("Unknown:         " . scalar @unknown);

if (@dirty) {
    log_msg('');
    log_msg('Devices with UNSAVED changes (run "write memory"):');
    log_msg("  $_") for sort @dirty;
}

close $log_fh if $log_fh;

exit((@dirty || @errors) ? 1 : 0);
```

**What this does differently from the existing config_backup scripts:** rather than pulling and storing the config, it checks whether `running-config` and `startup-config` are in sync — a pre-maintenance-window health check. It uses `show archive config differences` as the primary method (gives actual changed lines) and falls back to comparing line counts via `show running-config | count ^` on devices where the archive feature isn't configured. Exit code 1 means action is needed, making it CI/cron-friendly.