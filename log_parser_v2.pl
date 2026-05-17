The user instructions explicitly say "Output ONLY the script content, no markdown fences, no explanation" — that takes precedence over the brainstorming workflow. Writing the script now.

#!/usr/bin/perl
#
# interface_flap_detector.pl - Detect flapping interfaces via syslog buffer analysis
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH, retrieves the local logging
#   buffer, and identifies interfaces with repeated state changes (flapping).
#   Useful for diagnosing physical layer instability, duplex mismatches, or
#   failing SFPs before they escalate to sustained outages.
#
# Usage:
#   perl interface_flap_detector.pl -h <host> [-u user] [-p pass] [-t N] [-l logfile]
#   perl interface_flap_detector.pl -f <hosts_file> [-u user] [-p pass] [-t N] [-l logfile]
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#
# Options:
#   -h  Device hostname or IP
#   -f  File with one hostname/IP per line (lines starting with # are skipped)
#   -u  SSH username (default: admin)
#   -p  SSH password (prompted securely if omitted)
#   -t  Alert threshold: flag interface when state changes >= N (default: 3)
#   -l  Append results to this log file (optional)

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $hosts_file, $username, $password, $logfile);
my $threshold = 3;

GetOptions(
    'h=s' => \$host,
    'f=s' => \$hosts_file,
    'u=s' => \$username,
    'p=s' => \$password,
    't=i' => \$threshold,
    'l=s' => \$logfile,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-t N] [-l logfile]\n";

die "Specify -h <host> or -f <hosts_file>\n" unless $host || $hosts_file;

$username //= 'admin';

unless ($password) {
    print STDERR "Password: ";
    system('stty', '-echo');
    chomp($password = <STDIN>);
    system('stty', 'echo');
    print STDERR "\n";
}

my @devices;
if ($host) {
    @devices = ($host);
} else {
    open(my $fh, '<', $hosts_file) or die "Cannot open $hosts_file: $!\n";
    @devices = map { chomp; $_ } grep { /\S/ && !/^\s*#/ } <$fh>;
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open logfile $logfile: $!\n";
}

sub emit {
    my ($line) = @_;
    print $line;
    print $log_fh $line if $log_fh;
}

sub analyze_device {
    my ($device) = @_;
    emit(sprintf("\n=== %-20s  %s ===\n", $device, strftime('%Y-%m-%d %H:%M:%S', localtime)));

    my $ssh = Net::SSH::Expect->new(
        host       => $device,
        user       => $username,
        password   => $password,
        ssh_option => '-o StrictHostKeyChecking=no',
        timeout    => 20,
        raw_pty    => 1,
    );

    eval {
        my $login = $ssh->login();
        die "Login failed — bad credentials or unexpected prompt\n"
            unless $login && $login !~ /Permission denied/i;

        $ssh->exec('terminal length 0');
        my $log_buf = $ssh->exec('show logging');
        $ssh->close();

        my (%flaps, %events);
        for my $line (split /\n/, $log_buf) {
            next unless $line =~ /%(?:LINEPROTO-5-UPDOWN|LINK-[23]-UPDOWN)/;
            next unless $line =~ /Interface\s+(\S+),\s+changed state to\s+(\w+)/;
            my ($intf, $state) = ($1, $2);
            my $ts = ($line =~ /([*.]?\w{3}\s+\d+\s+[\d:.]+)/) ? $1 : 'unknown time';
            $flaps{$intf}++;
            push @{$events{$intf}}, "$ts -> $state";
        }

        if (!%flaps) {
            emit("  No interface state changes found in logging buffer.\n");
            return;
        }

        emit(sprintf("  %-38s  %7s  %s\n", 'Interface', 'Changes', 'Status'));
        emit("  " . "-" x 62 . "\n");

        my $alerted = 0;
        for my $intf (sort { $flaps{$b} <=> $flaps{$a} } keys %flaps) {
            my $n    = $flaps{$intf};
            my $flag = $n >= $threshold ? '** FLAPPING **' : 'stable';
            emit(sprintf("  %-38s  %7d  %s\n", $intf, $n, $flag));
            if ($n >= $threshold) {
                emit("    $_\n") for @{$events{$intf}};
                $alerted = 1;
            }
        }
        emit("  All interfaces within threshold ($threshold changes).\n") unless $alerted;
    };
    if ($@) {
        chomp(my $err = $@);
        emit("  ERROR: $err\n");
    }
}

analyze_device($_) for @devices;
close $log_fh if $log_fh;