#!/usr/bin/perl
use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# ntp_compliance_audit.pl - NTP Configuration Compliance Auditor
#
# Purpose:
#   Audits NTP configuration compliance across Cisco IOS/IOS-XE devices.
#   Validates NTP server configuration against a required server list,
#   checks authentication state, and flags stratum policy violations.
#   Distinct from ntp_check.pl (sync status) -- this focuses on CONFIGURATION
#   correctness: are the right servers configured, is auth enabled, is the
#   stratum within policy limits?
#
# Usage:
#   ./ntp_compliance_audit.pl -u admin -p secret -s 10.0.0.1,10.0.0.2
#   ./ntp_compliance_audit.pl -u admin -p secret -f devices.txt
#   ./ntp_compliance_audit.pl -u admin -p secret -f devices.txt -l audit.log
#                             --required-servers 10.1.1.1,10.1.1.2
#                             --max-stratum 4
#
# Options:
#   -u, --user            SSH username (required)
#   -p, --password        SSH password (required)
#   -s, --servers         Comma-separated device list
#   -f, --file            File with one device per line
#   -l, --log             Output log file path
#       --required-servers  Comma-separated list of NTP servers devices must use
#       --max-stratum       Maximum acceptable stratum (default: 5)
#   -t, --timeout         SSH timeout in seconds (default: 15)
#
# Prerequisites:
#   cpan install Expect Getopt::Long
#   SSH access to devices; enable password optional (script handles enable prompt)
#
# Output:
#   PASS/FAIL/WARN per device with specific compliance findings
# =============================================================================

my ($user, $pass, $server_arg, $device_file, $log_file);
my ($required_servers_arg, $max_stratum, $timeout) = ('', 5, 15);

GetOptions(
    'u|user=s'             => \$user,
    'p|password=s'         => \$pass,
    's|servers=s'          => \$server_arg,
    'f|file=s'             => \$device_file,
    'l|log=s'              => \$log_file,
    'required-servers=s'   => \$required_servers_arg,
    'max-stratum=i'        => \$max_stratum,
    't|timeout=i'          => \$timeout,
) or die "Usage: $0 -u USER -p PASS [-s DEVICE[,..] | -f FILE] [options]\n";

die "Error: --user and --password are required\n" unless $user && $pass;

my @devices;
push @devices, split(/,/, $server_arg) if $server_arg;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; push @devices, $_ if /\S/ && !/^#/ }
    close $fh;
}
die "Error: no devices specified (-s or -f required)\n" unless @devices;

my %required = map { $_ => 1 } split(/,/, $required_servers_arg);

my $log_fh;
if ($log_file) {
    open($log_fh, '>', $log_file) or warn "Cannot open log $log_file: $!\n";
}

sub emit {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
emit("NTP Compliance Audit  $ts\n" . "=" x 60 . "\n");
emit(sprintf("Policy: max_stratum=%d  required_servers=%s\n\n",
    $max_stratum, $required_servers_arg || '(any)'));

my ($pass_count, $fail_count, $warn_count) = (0, 0, 0);

for my $device (@devices) {
    $device =~ s/\s+//g;
    emit("Device: $device\n");

    my $exp = Expect->new;
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=$timeout $user\@$device")) {
        emit("  [FAIL] Connection failed: $!\n\n");
        $fail_count++;
        next;
    }

    my $result = $exp->expect($timeout,
        [ qr/[Pp]assword:/            => sub { $exp->send("$pass\n"); exp_continue } ],
        [ qr/yes\/no/                 => sub { $exp->send("yes\n");   exp_continue } ],
        [ qr/[>#]/                    => sub { 1 } ],
        [ timeout                     => sub { 0 } ],
    );

    unless ($result) {
        emit("  [FAIL] Auth timeout or connection refused\n\n");
        $fail_count++;
        $exp->soft_close;
        next;
    }

    $exp->send("terminal length 0\n");
    $exp->expect($timeout, qr/[>#]/);

    # Collect NTP associations
    $exp->send("show ntp associations\n");
    my $assoc_output = '';
    $exp->expect($timeout,
        [ qr/[>#]/ => sub { $assoc_output = $exp->before; } ]
    );

    # Collect running NTP config
    $exp->send("show running-config | include ntp\n");
    my $cfg_output = '';
    $exp->expect($timeout,
        [ qr/[>#]/ => sub { $cfg_output = $exp->before; } ]
    );

    $exp->send("exit\n");
    $exp->soft_close;

    # Parse configured NTP servers from running config
    my @configured_servers = ($cfg_output =~ /ntp server\s+(\S+)/gi);
    my $auth_enabled = ($cfg_output =~ /ntp authenticate/i) ? 1 : 0;
    my $auth_keys    = ($cfg_output =~ /ntp authentication-key/i) ? 1 : 0;
    my $trusted_keys = ($cfg_output =~ /ntp trusted-key/i) ? 1 : 0;

    # Parse stratum from associations output (synced peer marked with *)
    my ($synced_ip, $synced_stratum) = ('none', 'N/A');
    if ($assoc_output =~ /^\*(\d+\.\d+\.\d+\.\d+)\s+\S+\s+(\d+)/m) {
        ($synced_ip, $synced_stratum) = ($1, $2);
    }

    # Evaluate compliance
    my @issues;
    my @warnings;

    if (!@configured_servers) {
        push @issues, "No NTP servers configured";
    } else {
        if (%required) {
            for my $req (keys %required) {
                unless (grep { $_ eq $req } @configured_servers) {
                    push @issues, "Required NTP server $req not configured";
                }
            }
        }
    }

    if ($synced_stratum ne 'N/A' && $synced_stratum > $max_stratum) {
        push @issues, "Stratum $synced_stratum exceeds policy max ($max_stratum)";
    }
    if ($synced_ip eq 'none') {
        push @warnings, "Not synchronized to any NTP server";
    }
    if (!$auth_enabled || !$auth_keys || !$trusted_keys) {
        push @warnings, "NTP authentication not fully configured";
    }

    my $status = @issues ? 'FAIL' : (@warnings ? 'WARN' : 'PASS');
    @issues  ? $fail_count++ : (@warnings ? $warn_count++ : $pass_count++);

    emit("  Status   : [$status]\n");
    emit("  Synced to: $synced_ip  (stratum $synced_stratum)\n");
    emit("  Servers  : " . (@configured_servers ? join(', ', @configured_servers) : 'none') . "\n");
    emit("  Auth     : " . ($auth_enabled && $auth_keys && $trusted_keys ? 'configured' : 'INCOMPLETE') . "\n");

    for my $issue (@issues)   { emit("  [!] $issue\n") }
    for my $warn  (@warnings) { emit("  [W] $warn\n")  }
    emit("\n");
}

emit("=" x 60 . "\n");
emit(sprintf("Summary: %d PASS  %d WARN  %d FAIL  (%d total)\n",
    $pass_count, $warn_count, $fail_count, scalar @devices));

close $log_fh if $log_fh;
exit ($fail_count > 0 ? 1 : 0);