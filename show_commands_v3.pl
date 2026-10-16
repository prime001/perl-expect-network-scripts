#!/usr/bin/perl
#
# device_health.pl - Network Device Health Monitor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and collects CPU utilization,
#   memory utilization, environment (temperature/power) status, and process
#   summary. Useful for quick health checks before/after maintenance windows
#   or during incident triage.
#
# Usage:
#   ./device_health.pl <host|ip>                  # single device
#   ./device_health.pl -f devices.txt             # file with one host per line
#   ./device_health.pl -f devices.txt -l out.log  # with log file
#
# Prerequisites:
#   cpan install Expect
#   SSH key auth preferred; set DEVICE_PASSWORD env var for password auth
#   DEVICE_USER env var for username (default: admin)
#
# Environment vars:
#   DEVICE_USER     SSH username (default: admin)
#   DEVICE_PASSWORD SSH password (leave unset for key-based auth)
#   DEVICE_ENABLE   Enable password if needed
#

use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

my $TIMEOUT   = 30;
my $SSH_USER  = $ENV{DEVICE_USER}     // 'admin';
my $SSH_PASS  = $ENV{DEVICE_PASSWORD} // '';
my $EN_PASS   = $ENV{DEVICE_ENABLE}   // '';

my ($host_file, $log_file, $single_host);
GetOptions(
    'f=s' => \$host_file,
    'l=s' => \$log_file,
) or die "Usage: $0 [-f hosts_file] [-l log_file] [host]\n";

$single_host = shift @ARGV;
die "Provide a host or -f file\n" unless $single_host || $host_file;

my @hosts;
if ($host_file) {
    open my $fh, '<', $host_file or die "Cannot open $host_file: $!\n";
    @hosts = grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
    close $fh;
}
push @hosts, $single_host if $single_host;

my $LOG;
if ($log_file) {
    open $LOG, '>>', $log_file or die "Cannot open $log_file: $!\n";
    $LOG->autoflush(1);
}

sub log_out {
    my $line = strftime("[%Y-%m-%d %H:%M:%S] ", localtime) . $_[0];
    print $line;
    print $LOG $line if $LOG;
}

sub check_device {
    my ($host) = @_;
    log_out("=== Health check: $host ===\n");

    my @ssh_cmd = ('ssh', '-o', 'StrictHostKeyChecking=no',
                         '-o', 'ConnectTimeout=10',
                         '-l', $SSH_USER, $host);

    my $exp = Expect->new;
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn(@ssh_cmd)) {
        log_out("ERROR [$host]: spawn failed: $!\n");
        return 0;
    }

    my $prompt = qr/[>#]\s*$/;

    # Handle password auth if set
    if ($SSH_PASS) {
        $exp->expect($TIMEOUT,
            [ qr/[Pp]assword:/, sub { $exp->send("$SSH_PASS\n"); exp_continue; } ],
            [ $prompt, sub {} ],
            [ timeout => sub { log_out("ERROR [$host]: login timeout\n"); return 0; } ],
        );
    } else {
        $exp->expect($TIMEOUT,
            [ $prompt, sub {} ],
            [ timeout => sub { log_out("ERROR [$host]: connection timeout\n"); return 0; } ],
        );
    }

    # Enter enable mode if needed
    if ($EN_PASS) {
        $exp->send("enable\n");
        $exp->expect($TIMEOUT, [ qr/[Pp]assword:/, sub { $exp->send("$EN_PASS\n"); exp_continue; } ],
                               [ $prompt, sub {} ]);
    }

    $exp->send("terminal length 0\n");
    $exp->expect($TIMEOUT, [ $prompt, sub {} ]);

    my %cmds = (
        'CPU'   => 'show processes cpu | include CPU utilization',
        'MEM'   => 'show processes memory | include Processor',
        'ENV'   => 'show environment all | include Temperature|Power|FAIL|OK|Fan',
    );

    for my $label (sort keys %cmds) {
        $exp->send("$cmds{$label}\n");
        my $out = '';
        $exp->expect($TIMEOUT,
            [ $prompt, sub { $out = $exp->before(); } ],
            [ timeout => sub { $out = "[timeout]"; } ],
        );
        $out =~ s/^\s*\Q$cmds{$label}\E\s*//;  # strip echoed command
        $out =~ s/\r//g;
        for my $line (split /\n/, $out) {
            next unless $line =~ /\S/;
            log_out("  [$label] $line\n");
        }
    }

    $exp->send("exit\n");
    $exp->soft_close();
    log_out("=== Done: $host ===\n\n");
    return 1;
}

my $ok = 0; my $fail = 0;
for my $h (@hosts) {
    check_device($h) ? $ok++ : $fail++;
}

log_out("Summary: $ok ok, $fail failed\n");
close $LOG if $LOG;