```perl
#!/usr/bin/perl
#
# hardware_health.pl - Collect CPU, memory, and environmental health metrics
#                      from Cisco IOS/IOS-XE devices via SSH
#
# Purpose:
#   Polls CPU utilization, memory usage, temperature sensors, power supplies,
#   and fan status. Designed for routine health checks and pre/post-change
#   baselines. Distinct from inventory_collection (platform/version data).
#
# Usage:
#   Single device:  perl hardware_health.pl -h 192.168.1.1
#   Multiple hosts: perl hardware_health.pl -f hosts.txt
#   With logging:   perl hardware_health.pl -h 192.168.1.1 -o /var/log/health/
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access with at least privilege 1 (show commands only)
#   Environment: SSH_USER and SSH_PASS env vars, or use -u/-p flags
#
# Author: Erik Anderson
# Tested: Cisco IOS 15.x, IOS-XE 16.x/17.x

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);

my %opts;
getopts('h:f:u:p:o:', \%opts);

my $user    = $opts{u} || $ENV{SSH_USER} || 'admin';
my $pass    = $opts{p} || $ENV{SSH_PASS} or die "Password required: set SSH_PASS or use -p\n";
my $logdir  = $opts{o};
my @hosts;

if ($opts{h}) {
    push @hosts, $opts{h};
} elsif ($opts{f}) {
    open my $fh, '<', $opts{f} or die "Cannot open host file '$opts{f}': $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @hosts, $_;
    }
    close $fh;
} else {
    die "Usage: $0 -h <host> | -f <hostfile> [-u user] [-p pass] [-o logdir]\n";
}

my $timestamp = strftime('%Y%m%d_%H%M%S', localtime);

for my $host (@hosts) {
    print "\n=== $host [$timestamp] ===\n";

    my $log_fh;
    if ($logdir) {
        my $logfile = "$logdir/${host}_health_${timestamp}.log";
        open $log_fh, '>', $logfile or warn "Cannot write log '$logfile': $!\n";
    }

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $host,
            user        => $user,
            password    => $pass,
            ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
            raw_pty     => 1,
            timeout     => 15,
        );
    };
    if ($@ || !$ssh) {
        my $err = "ERROR: Cannot create SSH session to $host: $@";
        print "$err\n";
        print $log_fh "$err\n" if $log_fh;
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        my $err = "ERROR: Authentication failed for $host (user=$user)";
        print "$err\n";
        print $log_fh "$err\n" if $log_fh;
        next;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('\$\s*#', 5);

    my @commands = (
        ['CPU Utilization',   'show processes cpu sorted | head 15'],
        ['Memory Utilization','show processes memory sorted | head 10'],
        ['Environment',       'show environment all'],
    );

    for my $cmd_pair (@commands) {
        my ($label, $cmd) = @$cmd_pair;
        $ssh->send($cmd);
        my $output = eval { $ssh->waitfor('\S+#\s*$', 20, '-re') };
        if ($@) {
            my $msg = "TIMEOUT running '$cmd' on $host";
            print "  [$label] $msg\n";
            print $log_fh "[$label] $msg\n" if $log_fh;
            next;
        }

        $output =~ s/^\Q$cmd\E\r?\n//;
        $output =~ s/\S+#\s*$//;
        $output =~ s/\r//g;
        $output =~ s/^\s+|\s+$//g;

        my $section = "[$label]\n$output\n";
        print "$section\n";
        print $log_fh "$section\n" if $log_fh;
    }

    $ssh->send('exit');
    close $log_fh if $log_fh;
    print "--- done ---\n";
}
```