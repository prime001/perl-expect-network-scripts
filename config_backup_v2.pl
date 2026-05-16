The user wants only script content output with no explanation. The brainstorming skill would add overhead, but user instructions (output ONLY the script) take precedence. I'll write a startup-vs-running config diff script — distinct from the existing config_backup.pl scripts.

#!/usr/bin/perl
#
# startup_running_diff.pl - Detect unsaved configuration changes on Cisco IOS devices
#
# PURPOSE:
#   Connects to one or more network devices via SSH and compares the running
#   configuration against the startup configuration. Flags devices where changes
#   have been made but not written to NVRAM -- these devices would lose config
#   on reboot. Critical for change management audits and post-maintenance checks.
#
# USAGE:
#   perl startup_running_diff.pl -h <host> -u <user> -p <pass> [-o <logfile>]
#   perl startup_running_diff.pl -f <hostfile> -u <user> -p <pass> [-o <logfile>]
#
# PREREQUISITES:
#   cpanm Expect Getopt::Long
#
# HOSTFILE FORMAT:
#   One IP or hostname per line. Lines starting with # are ignored.
#
# ENVIRONMENT:
#   NET_USER  - fallback username if -u not provided
#   NET_PASS  - fallback password if -p not provided
#
# EXAMPLES:
#   perl startup_running_diff.pl -h 10.0.0.1 -u admin -p s3cr3t
#   perl startup_running_diff.pl -f core_switches.txt -u netops -o audit.log

use strict;
use warnings;
use Expect;
use Getopt::Long qw(:config no_ignore_case);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log, $opt_timeout);

GetOptions(
    'h|host=s'    => \$opt_host,
    'f|file=s'    => \$opt_file,
    'u|user=s'    => \$opt_user,
    'p|pass=s'    => \$opt_pass,
    'o|output=s'  => \$opt_log,
    't|timeout=i' => \$opt_timeout,
) or die "Usage: $0 -h <host>|-f <file> -u <user> -p <pass> [-o logfile] [-t timeout]\n";

my $username = $opt_user // $ENV{NET_USER} // die "Username required: use -u or set NET_USER\n";
my $password = $opt_pass // $ENV{NET_PASS} // die "Password required: use -p or set NET_PASS\n";
my $timeout  = $opt_timeout // 45;

my @devices;
if ($opt_file) {
    open my $fh, '<', $opt_file or die "Cannot open host file '$opt_file': $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
} elsif ($opt_host) {
    @devices = ($opt_host);
} else {
    die "Specify -h <host> or -f <hostfile>\n";
}

my $log_fh;
if ($opt_log) {
    open $log_fh, '>', $opt_log or die "Cannot open log file '$opt_log': $!\n";
}

sub emit {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub strip_noise {
    my ($text) = @_;
    return grep {
        /\S/
        && !/^Building configuration/
        && !/^Current configuration/
        && !/^NVRAM config last/
        && !/^Load for/
        && !/^Time source/
        && !/^\s*!/
    } split /\n/, $text;
}

sub check_device {
    my ($host) = @_;

    emit(sprintf("\n%-60s\n", "[ $host ]"));
    emit("-" x 60 . "\n");

    my $ssh_cmd = "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "
                . "-o BatchMode=no ${username}\@${host}";

    my $exp = Expect->new;
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn($ssh_cmd)) {
        emit("ERROR: Failed to spawn SSH to $host\n");
        return 'error';
    }

    my $authed = 0;
    $exp->expect($timeout,
        [ qr/[Pp]assword:/        => sub { $exp->send("$password\n"); exp_continue; } ],
        [ qr/yes\/no\)\?/         => sub { $exp->send("yes\n");       exp_continue; } ],
        [ qr/[>#]\s*$/            => sub { $authed = 1; } ],
        [ 'timeout'               => sub { emit("ERROR: Timeout during auth to $host\n"); } ],
        [ 'eof'                   => sub { emit("ERROR: Connection closed by $host\n"); } ],
    );

    unless ($authed) {
        $exp->soft_close;
        return 'error';
    }

    $exp->send("terminal length 0\n");
    $exp->expect($timeout, qr/[>#]\s*$/);

    $exp->send("show running-config\n");
    $exp->expect($timeout, qr/[>#]\s*$/);
    my @running = strip_noise($exp->before // '');

    $exp->send("show startup-config\n");
    $exp->expect($timeout, qr/[>#]\s*$/);
    my @startup = strip_noise($exp->before // '');

    $exp->send("exit\n");
    $exp->soft_close;

    my %run_set   = map { $_ => 1 } @running;
    my %start_set = map { $_ => 1 } @startup;

    my @unsaved  = grep { !$start_set{$_} } @running;
    my @removed  = grep { !$run_set{$_}   } @startup;

    if (!@unsaved && !@removed) {
        emit("STATUS: IN SYNC - Running matches startup, safe to reboot\n");
        return 'ok';
    }

    emit("STATUS: UNSAVED CHANGES DETECTED - write memory required before reboot\n");
    if (@unsaved) {
        emit("\n  In running, not in startup (changes pending write):\n");
        emit("    $_\n") for @unsaved;
    }
    if (@removed) {
        emit("\n  In startup, not in running (deletions pending write):\n");
        emit("    $_\n") for @removed;
    }
    return 'drift';
}

my $ts = localtime;
emit("Startup vs Running Config Audit\n");
emit("Generated : $ts\n");
emit("Devices   : " . scalar(@devices) . "\n");

my %summary = (ok => 0, drift => 0, error => 0);
for my $dev (@devices) {
    my $result = check_device($dev);
    $summary{$result}++;
}

emit("\n" . "=" x 60 . "\n");
emit(sprintf("Summary: %d in-sync  |  %d with drift  |  %d errors\n",
    $summary{ok}, $summary{drift}, $summary{error}));

close $log_fh if $log_fh;
exit($summary{drift} > 0 ? 1 : ($summary{error} > 0 ? 2 : 0));