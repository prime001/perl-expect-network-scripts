Writing the Perl Expect script now — a running-vs-startup config diff checker (distinct from the existing config_backup scripts which save configs).

#!/usr/bin/perl
use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# startup_running_diff.pl - Detect unsaved configuration changes on Cisco IOS
#
# PURPOSE:
#   Connects to one or more Cisco IOS devices and compares running-config
#   to startup-config. Reports which devices have uncommitted changes that
#   would be lost on reboot. Useful before maintenance windows, planned
#   reboots, or as a nightly hygiene check.
#
# USAGE:
#   ./startup_running_diff.pl -H 192.168.1.1 -u admin -p secret
#   ./startup_running_diff.pl -f devices.txt -u admin -p secret -l diff.log
#   ./startup_running_diff.pl -H 10.0.0.1,10.0.0.2 -u admin -p secret
#
# OPTIONS:
#   -H  Comma-separated list of device IPs/hostnames
#   -f  File containing one device per line (# = comment)
#   -u  SSH username
#   -p  SSH password
#   -e  Enable password (optional, for privilege escalation)
#   -l  Log file path (appends; default: stdout only)
#   -t  Timeout in seconds (default: 30)
#
# PREREQUISITES:
#   cpan Expect
#   Cisco IOS devices with SSH enabled, privilege 15 access recommended
# =============================================================================

my ($host_arg, $device_file, $username, $password, $enable_pass, $log_file);
my $timeout = 30;

GetOptions(
    'H=s' => \$host_arg,
    'f=s' => \$device_file,
    'u=s' => \$username,
    'p=s' => \$password,
    'e=s' => \$enable_pass,
    'l=s' => \$log_file,
    't=i' => \$timeout,
) or die "Usage: $0 -H host[,host] | -f file -u user -p pass [-e enable] [-l log] [-t sec]\n";

die "Provide -H or -f\n"    unless $host_arg || $device_file;
die "Username required (-u)\n" unless $username;
die "Password required (-p)\n" unless $password;

my @devices;
push @devices, split(/,/, $host_arg) if $host_arg;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if $_; }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub log_out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub get_config {
    my ($exp, $cmd, $prompt) = @_;
    $exp->send("$cmd\n");
    my @lines;
    while (1) {
        my $pos = $exp->expect($timeout, [$prompt, sub { last }], ['-re', '-- More --', sub { $exp->send(' '); 1 }]);
        last unless defined $pos && $pos == 2;
    }
    my $out = $exp->before() // '';
    return grep { !/^\s*$/ && !/^Building configuration/ && !/^Current configuration/ && !/^!.*Last configuration change/ && !/^! Last/ && !/^ntp clock-period/ } split(/\r?\n/, $out);
}

my $ts      = strftime('%Y-%m-%d %H:%M:%S', localtime);
my $summary = { clean => [], dirty => [], failed => [] };

log_out("=" x 60 . "\n");
log_out("Startup vs Running Config Diff Check  $ts\n");
log_out("=" x 60 . "\n\n");

for my $device (@devices) {
    log_out("[$device] Connecting...\n");

    my $exp = Expect->new();
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${username}\@${device}")) {
        log_out("[$device] ERROR: spawn failed\n\n");
        push @{$summary->{failed}}, $device;
        next;
    }

    my $res = $exp->expect($timeout,
        [qr/[Pp]assword:/,         sub { $exp->send("$password\n"); exp_continue; }],
        [qr/yes\/no/,              sub { $exp->send("yes\n");       exp_continue; }],
        [qr/[>#]/,                 sub { 1 }],
        [qr/Connection refused/,   sub { 0 }],
        [qr/No route to host/,     sub { 0 }],
        ['timeout',                sub { 0 }],
    );

    unless (defined $res && $res == 1) {
        log_out("[$device] ERROR: connection or auth failed\n\n");
        push @{$summary->{failed}}, $device;
        $exp->soft_close();
        next;
    }

    $exp->send("terminal length 0\n");
    $exp->expect($timeout, qr/[>#]/);

    if ($enable_pass && $exp->before() =~ /\>$/) {
        $exp->send("enable\n");
        $exp->expect($timeout, qr/[Pp]assword:/);
        $exp->send("$enable_pass\n");
        $exp->expect($timeout, qr/#/);
    }

    my $prompt = qr/[\w\-]+[>#]/;

    my @running  = get_config($exp, 'show running-config',  $prompt);
    my @startup  = get_config($exp, 'show startup-config',  $prompt);

    $exp->send("exit\n");
    $exp->soft_close();

    my %run_set  = map { $_ => 1 } @running;
    my %start_set = map { $_ => 1 } @startup;
    my @only_run   = grep { !$start_set{$_} } @running;
    my @only_start = grep { !$run_set{$_}   } @startup;

    if (@only_run == 0 && @only_start == 0) {
        log_out("[$device] CLEAN — running matches startup\n\n");
        push @{$summary->{clean}}, $device;
    } else {
        log_out("[$device] UNSAVED CHANGES (+run/-start): " . scalar(@only_run) . " added, " . scalar(@only_start) . " removed\n");
        log_out("  + $_\n") for (sort @only_run)[0..([scalar(@only_run)-1, 9]->[$#_[0] < 10 ? 0 : 1])];
        log_out("  - $_\n") for (sort @only_start)[0..([scalar(@only_start)-1, 9]->[$#_[0] < 10 ? 0 : 1])];
        log_out("  (showing up to 10 lines per side)\n") if @only_run > 10 || @only_start > 10;
        log_out("\n");
        push @{$summary->{dirty}}, $device;
    }
}

log_out("=" x 60 . "\n");
log_out(sprintf("SUMMARY: %d clean, %d unsaved, %d failed  (total: %d)\n",
    scalar @{$summary->{clean}}, scalar @{$summary->{dirty}},
    scalar @{$summary->{failed}}, scalar @devices));
log_out("  Unsaved: " . join(', ', @{$summary->{dirty}})  . "\n") if @{$summary->{dirty}};
log_out("  Failed:  " . join(', ', @{$summary->{failed}}) . "\n") if @{$summary->{failed}};
log_out("=" x 60 . "\n");

close $log_fh if $log_fh;
exit(scalar @{$summary->{dirty}} > 0 ? 1 : 0);