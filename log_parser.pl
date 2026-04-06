#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# 009_log_parser.pl - Network Device Syslog Event Parser
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH, retrieves syslog buffer
#   output, and parses it for critical events including interface state changes,
#   BGP/OSPF adjacency drops, authentication failures, and hardware errors.
#   Useful for rapid post-incident review or daily health checks across a fleet.
#
# Usage:
#   Single device:  ./009_log_parser.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    ./009_log_parser.pl -f devices.txt -u admin -p secret
#   With log file:  ./009_log_parser.pl -h 10.0.0.1 -u admin -p secret -o /var/log/net_events.log
#   Severity filter: ./009_log_parser.pl -h 10.0.0.1 -u admin -p secret -s critical
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH key auth or password auth to target devices
#   Devices must have 'logging buffered' configured
#
# Supported platforms: Cisco IOS, IOS-XE (tested on 15.x, 16.x, 17.x)
# =============================================================================

my ($host, $username, $password, $device_file, $log_file, $severity_filter, $timeout);
$timeout = 30;
$severity_filter = 'all';

GetOptions(
    'h|host=s'     => \$host,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'f|file=s'     => \$device_file,
    'o|output=s'   => \$log_file,
    's|severity=s' => \$severity_filter,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h <host> | -f <file> -u <user> -p <pass> [-o <logfile>] [-s <severity>]\n";

die "Provide -h <host> or -f <file>\n" unless $host || $device_file;
die "Username required (-u)\n" unless $username;
die "Password required (-p)\n" unless $password;

my @devices = $host ? ($host) : read_device_file($device_file);
die "No devices to process\n" unless @devices;

my $log_fh;
if ($log_file) {
    open($log_fh, '>>', $log_file) or die "Cannot open log file $log_file: $!\n";
}

my %severity_keywords = (
    critical => [qr/\%.*-[0-2]-/],
    error    => [qr/\%.*-[0-3]-/],
    warning  => [qr/\%.*-[0-4]-/],
    all      => [qr/\%[A-Z]/],
);

my @patterns_of_interest = (
    { regex => qr/LINEPROTO.*changed state to (down|up)/i,        label => 'INTERFACE_STATE' },
    { regex => qr/LINK.*changed state to (down|up)/i,             label => 'LINK_STATE'      },
    { regex => qr/ADJCHG.*Adj.*from \S+ to \S+/i,                 label => 'OSPF_ADJCHANGE'  },
    { regex => qr/BGP.*neighbor.*\b(Active|Idle|Established)\b/i, label => 'BGP_STATE'       },
    { regex => qr/SYS-5-CONFIG_I/,                                 label => 'CONFIG_CHANGE'   },
    { regex => qr/SEC_LOGIN.*LOGIN_FAILED/i,                       label => 'AUTH_FAILURE'    },
    { regex => qr/ENVIRONMENT.*Temp.*alarm/i,                      label => 'HARDWARE_TEMP'   },
    { regex => qr/FAN.*fail/i,                                     label => 'HARDWARE_FAN'    },
    { regex => qr/PLATFORM.*error/i,                               label => 'PLATFORM_ERROR'  },
    { regex => qr/SYS-3-CPUHOG/,                                   label => 'CPU_HOG'         },
);

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
log_output("=== Log Parse Run: $ts ===\n");

for my $device (@devices) {
    $device =~ s/\s+//g;
    next unless $device && $device !~ /^#/;
    log_output("\n--- Device: $device ---\n");
    parse_device_logs($device);
}

close($log_fh) if $log_fh;

sub parse_device_logs {
    my ($target) = @_;
    my $ssh;

    eval {
        $ssh = Net::SSH::Expect->new(
            host        => $target,
            user        => $username,
            password    => $password,
            raw_pty     => 1,
            timeout     => $timeout,
            ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
        $ssh->login() or die "Authentication failed\n";
    };
    if ($@) {
        log_output("[ERROR] $target: Connection/auth failed - $@\n");
        return;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\S+[#>]\s*$', 5);

    $ssh->send("show logging\n");
    my $output = $ssh->waitfor('\S+[#>]\s*$', $timeout);

    unless ($output) {
        log_output("[WARN] $target: No output from 'show logging'\n");
        $ssh->close();
        return;
    }

    my %event_counts;
    my @matched_lines;
    my $sev_re = $severity_keywords{$severity_filter} // $severity_keywords{all};

    for my $line (split /\n/, $output) {
        next unless $line =~ $sev_re->[0];
        for my $pat (@patterns_of_interest) {
            if ($line =~ $pat->{regex}) {
                $event_counts{ $pat->{label} }++;
                push @matched_lines, sprintf("  [%-18s] %s", $pat->{label}, $line);
                last;
            }
        }
    }

    if (@matched_lines) {
        log_output("Events found on $target:\n");
        log_output("$_\n") for @matched_lines;
        log_output("\nSummary for $target:\n");
        for my $label (sort keys %event_counts) {
            log_output(sprintf("  %-20s : %d occurrence(s)\n", $label, $event_counts{$label}));
        }
    } else {
        log_output("No notable events found on $target (filter: $severity_filter)\n");
    }

    $ssh->send("exit\n");
    $ssh->close();
}

sub read_device_file {
    my ($file) = @_;
    open(my $fh, '<', $file) or die "Cannot open device file $file: $!\n";
    my @hosts = <$fh>;
    close($fh);
    chomp @hosts;
    return grep { $_ && $_ !~ /^#/ } @hosts;
}

sub log_output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}