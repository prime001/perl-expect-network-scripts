```perl
#!/usr/bin/perl
# =============================================================================
# syslog_analyzer.pl - Cisco IOS/IOS-XE Syslog Severity Analyzer
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH, retrieves the syslog buffer,
#   and classifies entries by severity level (0-7). Detects common event
#   patterns: interface flaps, memory pressure, CPU spikes, auth failures,
#   and routing protocol changes. Useful for rapid triage during incidents or
#   as part of a scheduled health check pipeline.
#
# Usage:
#   ./syslog_analyzer.pl <device_ip> [--user USER] [--pass PASS] [--log FILE]
#   ./syslog_analyzer.pl --file devices.txt [--user USER] [--pass PASS] [--log FILE]
#
# Options:
#   --user <username>   SSH username (default: admin)
#   --pass <password>   SSH password (prompted securely if omitted)
#   --log  <file>       Append output to log file in addition to STDOUT
#   --file <file>       Read device IPs/hostnames from file (one per line)
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH access (port 22) with 'show logging' privilege on target devices
#
# Examples:
#   ./syslog_analyzer.pl 10.0.1.1 --user netops --log /var/log/syslog_rpt.txt
#   ./syslog_analyzer.pl --file routers.txt --user netops --pass s3cret
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX        qw(strftime);

my ($opt_file, $opt_user, $opt_pass, $opt_log);
GetOptions(
    'file=s' => \$opt_file,
    'user=s' => \$opt_user,
    'pass=s' => \$opt_pass,
    'log=s'  => \$opt_log,
) or die "Usage: $0 <device_ip> [--file FILE] [--user USER] [--pass PASS] [--log FILE]\n";

$opt_user //= 'admin';

my @devices;
if ($opt_file) {
    open(my $fh, '<', $opt_file) or die "Cannot open device file '$opt_file': $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if $_ }
    close $fh;
} elsif (@ARGV) {
    push @devices, shift @ARGV;
} else {
    die "Usage: $0 <device_ip> [options]\n       $0 --file devices.txt [options]\n";
}

unless ($opt_pass) {
    print STDERR "Password: ";
    system('stty -echo 2>/dev/null');
    chomp($opt_pass = <STDIN>);
    system('stty echo 2>/dev/null');
    print STDERR "\n";
}

my $log_fh;
if ($opt_log) {
    open($log_fh, '>>', $opt_log) or die "Cannot open log file '$opt_log': $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my %SEV_NAME = (
    0 => 'EMERG', 1 => 'ALERT', 2 => 'CRIT',  3 => 'ERROR',
    4 => 'WARN',  5 => 'NOTICE',6 => 'INFO',   7 => 'DEBUG',
);

my @PATTERNS = (
    { re => qr/line protocol.*down|changed state to down/i, tag => 'Interface Down'        },
    { re => qr/line protocol.*up|changed state to up/i,     tag => 'Interface Up'          },
    { re => qr/memory.*low|insufficient memory/i,           tag => 'Memory Pressure'       },
    { re => qr/cpu.*threshold|high cpu utilization/i,       tag => 'CPU Spike'             },
    { re => qr/authentication fail|login fail|bad password/i,tag => 'Auth Failure'         },
    { re => qr/neighbor.*down|adjacency.*lost|peer.*down/i, tag => 'Routing Proto Event'   },
    { re => qr/sec_login|login.*denied|access.list.*denied/i,tag => 'Security Event'       },
);

sub analyze {
    my ($device) = @_;
    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
    out("\n" . ('=' x 62) . "\n");
    out("  Device : $device\n  Time   : $ts\n");
    out(('=' x 62) . "\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $opt_user,
        password => $opt_pass,
        raw_pty  => 1,
        timeout  => 30,
    );

    my $output = eval {
        $ssh->run_ssh()                          or die "SSH failed to start\n";
        $ssh->waitfor('assword:\s*$', 10)        or die "Password prompt timed out\n";
        $ssh->send($opt_pass);
        $ssh->waitfor('[>#]\s*$', 15)            or die "Login timed out (bad credentials?)\n";
        $ssh->send("terminal length 0");
        $ssh->waitfor('[>#]\s*$', 10);
        $ssh->send("show logging");
        my $buf = $ssh->waitfor('[>#]\s*$', 45)  or die "Command timed out\n";
        $ssh->send("exit");
        $buf;
    };
    if ($@) { (my $e = $@) =~ s/\n$//; out("  ERROR: $e\n"); return }

    my (%sev, %hits);
    for my $line (split /\n/, $output) {
        next unless $line =~ /%[A-Z0-9]+-(\d)-[A-Z0-9_]+:/;
        my $s = $1;
        $sev{$s}++;
        for my $p (@PATTERNS) {
            push @{$hits{$p->{tag}}}, $line if $line =~ $p->{re};
        }
    }

    if (%sev) {
        out("\n  Severity Counts:\n");
        for my $s (sort keys %sev) {
            out(sprintf("    [%d] %-8s  %4d msg(s)\n", $s, $SEV_NAME{$s}//"SEV$s", $sev{$s}));
        }
    } else {
        out("  No structured syslog entries found (buffer may be empty).\n");
    }

    if (%hits) {
        out("\n  Event Patterns Detected:\n");
        for my $tag (sort keys %hits) {
            my @entries = @{$hits{$tag}};
            out(sprintf("    %-22s  %d occurrence(s)\n", $tag . ':', scalar @entries));
            for my $e (@entries) {
                $e =~ s/^\s+|\s+$//g;
                out("      > $e\n");
            }
        }
    } else {
        out("\n  No notable event patterns detected.\n");
    }
}

analyze($_) for @devices;
out("\nAnalysis complete.\n");
close $log_fh if $log_fh;
```