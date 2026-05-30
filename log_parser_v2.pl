```perl
#!/usr/bin/perl
#
# security_event_parser.pl - Network Device Security Log Analyzer
#
# PURPOSE:
#   Connects to Cisco IOS/IOS-XE devices via SSH, retrieves the syslog
#   buffer, and parses for security-relevant events: authentication
#   failures, ACL deny hits, port security violations, unauthorized
#   login attempts, and configuration changes. Useful for daily security
#   hygiene checks and post-incident investigation.
#
# USAGE:
#   ./security_event_parser.pl --host <ip> --user <username> [options]
#   ./security_event_parser.pl --file <device_list.txt> --user <username>
#
# OPTIONS:
#   --host    <ip/hostname>  Single device to audit
#   --file    <path>         File with one device IP per line
#   --user    <username>     SSH username (required)
#   --pass    <password>     SSH password (prompted if omitted)
#   --log     <logfile>      Append output to logfile in addition to STDOUT
#   --lines   <n>            Log lines to retrieve per device (default: 500)
#   --timeout <n>            SSH timeout in seconds (default: 30)
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   cpan Term::ReadKey
#
# NOTES:
#   Cisco IOS devices must have 'logging buffered' configured.
#   SSH access must be enabled and permitted from the calling host.
#   Tested against IOS 15.x and IOS-XE 16.x/17.x.
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log);
my $opt_lines   = 500;
my $opt_timeout = 30;

GetOptions(
    'host=s'    => \$opt_host,
    'file=s'    => \$opt_file,
    'user=s'    => \$opt_user,
    'pass=s'    => \$opt_pass,
    'log=s'     => \$opt_log,
    'lines=i'   => \$opt_lines,
    'timeout=i' => \$opt_timeout,
) or die "Usage: $0 --host <ip> --user <user> [--pass <pass>] [--log <file>]\n";

die "ERROR: --user is required\n"             unless $opt_user;
die "ERROR: --host or --file is required\n"   unless $opt_host || $opt_file;

unless ($opt_pass) {
    eval { require Term::ReadKey };
    if ($@) {
        print "Password: ";
        chomp($opt_pass = <STDIN>);
    } else {
        Term::ReadKey::ReadMode('noecho');
        print "Password: ";
        chomp($opt_pass = <STDIN>);
        Term::ReadKey::ReadMode('restore');
        print "\n";
    }
}

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open(my $fh, '<', $opt_file) or die "Cannot open '$opt_file': $!\n";
    while (<$fh>) { chomp; next if /^\s*$/ || /^#/; push @devices, $_; }
    close($fh);
}

my $log_fh;
if ($opt_log) {
    open($log_fh, '>>', $opt_log) or die "Cannot open log '$opt_log': $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my %patterns = (
    'Auth Failure'    => qr/%SEC_LOGIN-4-LOGIN_FAILED|Authentication failed|Invalid password/i,
    'ACL Deny'        => qr/%SEC-6-IPACCESSLOG[SP]?:|list \S+ denied/i,
    'Port Security'   => qr/%PORT_SECURITY-2-PSECURE_VIOLATION/i,
    'SSH Error'       => qr/%SSH-[34]-|%CRYPTO-4-/i,
    'AAA Failure'     => qr/%AAA-3-|%AUTHMGR-5-FAIL|RADIUS.*failed|TACACS.*failed/i,
    'Config Change'   => qr/%SYS-5-CONFIG_I|Configured from console|Configured from \d/i,
    'STP Event'       => qr/%SPANTREE-5-TOPOTCHANGE|%STP-5-TOPOLOGY_CHANGE/i,
    'Link Down'       => qr/%LINEPROTO-5-UPDOWN.*changed state to down/i,
);

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
out("=" x 68 . "\n");
out("Security Event Analysis  |  $ts\n");
out("=" x 68 . "\n\n");

for my $device (@devices) {
    out("Device: $device\n" . "-" x 40 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $opt_user,
        password => $opt_pass,
        timeout  => $opt_timeout,
        raw_pty  => 1,
    );

    eval {
        my $login = $ssh->login();
        die "Authentication failed\n" if $login =~ /[Pp]assword/i && $login !~ /[#>]/;
    };
    if ($@) {
        chomp(my $err = $@);
        out("  ERROR: $err\n\n");
        next;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\#', 5);

    $ssh->send("show logging | tail $opt_lines");
    my $output = $ssh->waitfor('\#', 60);

    unless ($output) {
        out("  ERROR: No response to 'show logging'\n\n");
        $ssh->close();
        next;
    }

    my (%counts, @recent);
    for my $line (split /\n/, $output) {
        for my $type (keys %patterns) {
            if ($line =~ $patterns{$type}) {
                $counts{$type}++;
                push @recent, [$type, $line] if @recent < 12;
                last;
            }
        }
    }

    my $total = 0;
    $total += $_ for values %counts;

    if ($total == 0) {
        out("  No security events found in log buffer\n");
    } else {
        out("  Summary ($total total events):\n");
        for my $t (sort { $counts{$b} <=> $counts{$a} } keys %counts) {
            out(sprintf("    %-20s %4d\n", $t, $counts{$t}));
        }
        out("\n  Recent matches:\n");
        for my $ev (@recent) {
            (my $line = $ev->[1]) =~ s/^\s+//;
            $line = substr($line, 0, 110) . (length($line) > 110 ? '...' : '');
            out("    [$ev->[0]] $line\n");
        }
    }

    out("\n");
    $ssh->send("exit");
    $ssh->close();
}

out("Done.\n");
close($log_fh) if $log_fh;
```