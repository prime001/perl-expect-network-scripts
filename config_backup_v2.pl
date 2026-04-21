#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);
use File::Basename;
use File::Path qw(make_path);

# =============================================================================
# config_diff.pl - Network Device Configuration Change Detector
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH, retrieves the running
#   configuration, and compares it against a previously saved baseline.
#   Highlights configuration drift for change management and audit trails.
#
# Usage:
#   perl config_diff.pl --host <ip_or_hostname> [options]
#   perl config_diff.pl --file <device_list.txt> [options]
#
# Options:
#   --host   <host>       Single device IP or hostname
#   --file   <file>       File with one device per line (IP user pass format)
#   --user   <username>   SSH username (default: admin)
#   --pass   <password>   SSH password
#   --dir    <directory>  Baseline storage directory (default: ./baselines)
#   --log    <logfile>    Optional log file path
#   --update              Save current config as new baseline after diff
#   --timeout <secs>      SSH timeout in seconds (default: 30)
#
# Prerequisites:
#   cpan Net::SSH::Expect
#
# Output:
#   Prints unified diff of configuration changes to STDOUT.
#   If no baseline exists, saves current config as initial baseline.
#
# Author:  Network Engineering
# Version: 1.0
# =============================================================================

my ($host, $device_file, $user, $pass, $baseline_dir, $log_file, $update, $timeout);
$user        = 'admin';
$baseline_dir = './baselines';
$timeout     = 30;

GetOptions(
    'host=s'    => \$host,
    'file=s'    => \$device_file,
    'user=s'    => \$user,
    'pass=s'    => \$pass,
    'dir=s'     => \$baseline_dir,
    'log=s'     => \$log_file,
    'update'    => \$update,
    'timeout=i' => \$timeout,
) or die "Usage: $0 --host <host> --user <user> --pass <pass> [--dir <dir>] [--log <file>] [--update]\n";

die "Provide --host or --file\n" unless $host || $device_file;
die "Password required (--pass)\n" unless $pass;

make_path($baseline_dir) unless -d $baseline_dir;

my @devices;
if ($host) {
    push @devices, { host => $host, user => $user, pass => $pass };
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp; next if /^\s*#/ || /^\s*$/;
        my ($h, $u, $p) = split /\s+/;
        push @devices, { host => $h, user => $u || $user, pass => $p || $pass };
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or warn "Cannot open log $log_file: $!\n";
}

sub log_msg {
    my $msg = shift;
    my $ts  = strftime('%Y-%m-%d %H:%M:%S', localtime);
    print "[$ts] $msg\n";
    print $log_fh "[$ts] $msg\n" if $log_fh;
}

sub fetch_config {
    my ($dev) = @_;
    my $ssh = Net::SSH::Expect->new(
        host        => $dev->{host},
        user        => $dev->{user},
        password    => $dev->{pass},
        raw_pty     => 1,
        timeout     => $timeout,
    );

    my $login = eval { $ssh->login() };
    if ($@) {
        log_msg("ERROR [$dev->{host}] Login failed: $@");
        return undef;
    }
    if (!$login || $login =~ /denied|fail/i) {
        log_msg("ERROR [$dev->{host}] Authentication failed");
        return undef;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('\$|\#|>', 5);
    $ssh->send('show running-config');
    my $output = $ssh->waitfor('\#', $timeout);

    unless ($output) {
        log_msg("ERROR [$dev->{host}] No response to show running-config");
        return undef;
    }

    $ssh->send('exit');
    $ssh->close();

    $output =~ s/\r//g;
    $output =~ s/^.*?^Building configuration\.\.\./Building configuration.../ms;
    $output =~ s/\#\s*$//;
    return $output;
}

sub load_baseline {
    my ($host) = @_;
    my $file = "$baseline_dir/${host}.baseline";
    return undef unless -f $file;
    open my $fh, '<', $file or return undef;
    my $content = do { local $/; <$fh> };
    close $fh;
    return $content;
}

sub save_baseline {
    my ($host, $config) = @_;
    my $file = "$baseline_dir/${host}.baseline";
    open my $fh, '>', $file or die "Cannot write baseline $file: $!\n";
    print $fh $config;
    close $fh;
}

sub diff_configs {
    my ($old, $new, $host) = @_;
    my $old_file = "/tmp/${host}_old_$$.tmp";
    my $new_file = "/tmp/${host}_new_$$.tmp";
    open(my $of, '>', $old_file) or return "Cannot create temp file\n";
    print $of $old; close $of;
    open(my $nf, '>', $new_file) or return "Cannot create temp file\n";
    print $nf $new; close $nf;
    my $diff = `diff -u --label "baseline" --label "current" "$old_file" "$new_file" 2>/dev/null`;
    unlink $old_file, $new_file;
    return $diff;
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
log_msg("=== Config Diff Run: $timestamp ===");

for my $dev (@devices) {
    log_msg("Connecting to $dev->{host}...");
    my $config = fetch_config($dev);
    next unless $config;

    my $baseline = load_baseline($dev->{host});
    if (!$baseline) {
        log_msg("[$dev->{host}] No baseline found — saving current config as baseline");
        save_baseline($dev->{host}, $config);
        next;
    }

    if ($config eq $baseline) {
        log_msg("[$dev->{host}] No configuration changes detected");
    } else {
        my $diff = diff_configs($baseline, $config, $dev->{host});
        log_msg("[$dev->{host}] CONFIGURATION DRIFT DETECTED:");
        print $diff;
        print $log_fh $diff if $log_fh;

        my @additions = ($diff =~ /^\+[^+]/mg);
        my @removals  = ($diff =~ /^-[^-]/mg);
        log_msg(sprintf("[$dev->{host}] Summary: +%d lines added, -%d lines removed",
            scalar @additions, scalar @removals));

        if ($update) {
            save_baseline($dev->{host}, $config);
            log_msg("[$dev->{host}] Baseline updated");
        }
    }
}

close $log_fh if $log_fh;