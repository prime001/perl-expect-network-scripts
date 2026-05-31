```perl
#!/usr/bin/perl
# =============================================================================
# config_drift.pl — Configuration Drift Detector for Cisco IOS/IOS-XE
# =============================================================================
# Purpose:
#   Compares the current running-config on one or more devices against a
#   previously saved baseline, flagging unauthorized or untracked changes.
#   Useful for change-control audits and post-maintenance verification.
#
# Usage:
#   Single device:   ./config_drift.pl --host 10.0.0.1 --baseline /backups/r1.cfg
#   Multiple hosts:  ./config_drift.pl --file devices.txt --baseline-dir /backups/
#   With log:        ./config_drift.pl --host 10.0.0.1 --baseline r1.cfg --log drift.log
#
# devices.txt format: one entry per line — IP/hostname, optionally followed by
#   a baseline path override:  10.0.0.1 /backups/r1.cfg
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   Credentials via ENV (NET_USER / NET_PASS) or --user / --password flags.
#   Key-based auth works automatically if SSH keys are configured.
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_baseline, $opt_baseline_dir, $opt_log);
my $opt_user    = $ENV{NET_USER} // 'admin';
my $opt_pass    = $ENV{NET_PASS} // '';
my $opt_timeout = 30;

GetOptions(
    'host=s'         => \$opt_host,
    'file=s'         => \$opt_file,
    'baseline=s'     => \$opt_baseline,
    'baseline-dir=s' => \$opt_baseline_dir,
    'log=s'          => \$opt_log,
    'user=s'         => \$opt_user,
    'password=s'     => \$opt_pass,
    'timeout=i'      => \$opt_timeout,
) or die "Usage: $0 --host <ip> --baseline <file> [options]\n";

die "Specify --host or --file\n" unless $opt_host || $opt_file;

my $log_fh;
if ($opt_log) {
    open($log_fh, '>>', $opt_log) or die "Cannot open log '$opt_log': $!\n";
}

sub emit {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub fetch_running_config {
    my ($host) = @_;

    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $opt_user,
        password => $opt_pass,
        raw_pty  => 1,
        timeout  => $opt_timeout,
    );

    eval { $ssh->login() };
    die "Login failed: $@\n" if $@;

    $ssh->exec("terminal length 0");
    my $raw = $ssh->exec("show running-config");
    $ssh->close();

    # Drop prompt lines and blank lines; keep config body
    my @lines = grep { $_ !~ /^[\w\-]+[>#]/ && $_ =~ /\S/ } split(/\n/, $raw);
    return \@lines;
}

sub diff_configs {
    my ($host, $current_lines, $baseline_path) = @_;

    unless (-f $baseline_path) {
        emit("  [SKIP]  No baseline at $baseline_path\n");
        return 0;
    }

    open(my $fh, '<', $baseline_path) or die "Cannot read baseline '$baseline_path': $!\n";
    my @baseline = grep { /\S/ } <$fh>;
    close($fh);
    chomp @baseline;

    # Noise patterns: cert blocks, timestamps, counters — not meaningful for drift
    my $noise = qr/^(?:Building config|Current config|Last config|
                       ntp\s+clock-period|\s*[0-9A-F]{2}(?:\s+[0-9A-F]{2})+|\s*quit)/x;

    my %base_set; $base_set{$_}++ for @baseline;
    my %curr_set; $curr_set{$_}++ for @$current_lines;

    my @added   = grep { !$base_set{$_} && !/$noise/ } @$current_lines;
    my @removed = grep { !$curr_set{$_} && !/$noise/ } @baseline;

    if (@added || @removed) {
        emit("  [DRIFT] $host — " . scalar(@added) . " added, " . scalar(@removed) . " removed\n");
        emit("    + $_\n") for @added;
        emit("    - $_\n") for @removed;
        return 1;
    }

    emit("  [OK]    $host matches baseline\n");
    return 0;
}

sub check_device {
    my ($host, $bl_override) = @_;

    emit("Checking $host ... ");

    my $bl_path = $bl_override
        // ($opt_baseline_dir ? "$opt_baseline_dir/${host}.cfg" : $opt_baseline);

    unless ($bl_path) {
        emit("[ERROR] no baseline path for $host\n");
        return 0;
    }

    my $current;
    eval { $current = fetch_running_config($host) };
    if ($@) {
        emit("[ERROR] $@");
        return 0;
    }

    return diff_configs($host, $current, $bl_path);
}

# Build target list
my @targets;
if ($opt_host) {
    push @targets, [ $opt_host, $opt_baseline ];
} else {
    open(my $fh, '<', $opt_file) or die "Cannot open device file '$opt_file': $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g; next unless /\S/;
        my ($dev, $bl) = split(/\s+/, $_, 2);
        push @targets, [ $dev, $bl ];
    }
    close($fh);
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
emit("=== Config Drift Check — $ts | " . scalar(@targets) . " device(s) ===\n");

my $drifted = 0;
$drifted += check_device(@$_) for @targets;

emit("\n=== Result: $drifted/" . scalar(@targets) . " device(s) have configuration drift ===\n");
close($log_fh) if $log_fh;
exit($drifted > 0 ? 1 : 0);
```