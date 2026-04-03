```perl
#!/usr/bin/perl
# =============================================================================
# 005_config_backup.pl - Network Device Configuration Backup
# =============================================================================
# PURPOSE:
#   Connects to one or more network devices via SSH and saves the running
#   configuration to timestamped local files. Supports Cisco IOS, IOS-XE,
#   and NX-OS platforms with automatic prompt detection.
#
# USAGE:
#   Single device:   ./005_config_backup.pl -h 192.168.1.1 -u admin -p secret
#   Device list:     ./005_config_backup.pl -f devices.txt -u admin -p secret
#   With log:        ./005_config_backup.pl -h 10.0.0.1 -u admin -p secret -l backup.log
#   Custom out dir:  ./005_config_backup.pl -f devices.txt -u admin -p secret -o /backups
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   cpan Getopt::Long
#
# DEVICES FILE FORMAT (one per line, lines starting with # are comments):
#   192.168.1.1
#   router01.example.com
#   10.0.0.254
#
# OUTPUT:
#   ./configs/<hostname>_<YYYYMMDD_HHMMSS>.cfg  (or -o dir)
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);
use File::Path qw(make_path);

# ---- CLI argument parsing ---------------------------------------------------
my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log, $opt_outdir);
$opt_outdir = './configs';

GetOptions(
    'h|host=s'     => \$opt_host,
    'f|file=s'     => \$opt_file,
    'u|user=s'     => \$opt_user,
    'p|pass=s'     => \$opt_pass,
    'l|log=s'      => \$opt_log,
    'o|outdir=s'   => \$opt_outdir,
) or usage();

usage() unless ($opt_host || $opt_file) && $opt_user && $opt_pass;

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open(my $fh, '<', $opt_file) or die "Cannot open device file '$opt_file': $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
    die "No devices found in '$opt_file'\n" unless @devices;
}

make_path($opt_outdir) unless -d $opt_outdir;

my $log_fh;
if ($opt_log) {
    open($log_fh, '>>', $opt_log) or die "Cannot open log '$opt_log': $!\n";
    $log_fh->autoflush(1);
}

# ---- Main loop -------------------------------------------------------------
my ($ok, $fail) = (0, 0);
for my $device (@devices) {
    my $result = backup_device($device, $opt_user, $opt_pass, $opt_outdir);
    if ($result) { $ok++ } else { $fail++ }
}

log_msg(sprintf("Done. Success: %d  Failed: %d", $ok, $fail));
close $log_fh if $log_fh;
exit($fail ? 1 : 0);

# ---- Subroutines -----------------------------------------------------------
sub backup_device {
    my ($host, $user, $pass, $outdir) = @_;
    log_msg("[$host] Connecting...");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $user,
        password     => $pass,
        raw_pty     => 1,
        timeout     => 15,
    );

    eval { $ssh->login() };
    if ($@) {
        log_msg("[$host] ERROR: Login failed - $@");
        return 0;
    }

    # Disable paging so we get full output
    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#|>', 5);

    # Detect privilege level; enter enable if needed
    my $prompt = $ssh->before() // '';
    if ($prompt =~ />/) {
        $ssh->send("enable");
        my $en = $ssh->waitfor('Password:|#', 5);
        if ($en && $ssh->before() =~ /Password:/) {
            $ssh->send($pass);
            $ssh->waitfor('#', 5);
        }
    }

    # Capture running config
    $ssh->send("show running-config");
    my $config = $ssh->waitfor('(?:end\r?\n[^\n]*#)', 30);

    unless ($config && length($config) > 100) {
        log_msg("[$host] ERROR: Empty or truncated config received");
        $ssh->close();
        return 0;
    }

    # Strip terminal escape sequences and leading cruft
    $config = $ssh->before() . ($ssh->match() // '');
    $config =~ s/\x1b\[[0-9;]*[mGKHF]//g;
    $config =~ s/\r\n/\n/g;

    my $ts       = strftime('%Y%m%d_%H%M%S', localtime);
    my $safe     = $host;
    $safe        =~ s/[^A-Za-z0-9._-]/_/g;
    my $filename = "$outdir/${safe}_${ts}.cfg";

    open(my $out, '>', $filename) or do {
        log_msg("[$host] ERROR: Cannot write '$filename': $!");
        $ssh->close();
        return 0;
    };
    print $out $config;
    close $out;

    my $lines = () = $config =~ /\n/g;
    log_msg("[$host] Saved $lines lines -> $filename");

    $ssh->send("exit");
    $ssh->close();
    return 1;
}

sub log_msg {
    my ($msg) = @_;
    my $ts  = strftime('%Y-%m-%d %H:%M:%S', localtime);
    my $line = "[$ts] $msg";
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}

sub usage {
    print <<'USAGE';
Usage:
  005_config_backup.pl -h <host>        -u <user> -p <pass> [-l log] [-o outdir]
  005_config_backup.pl -f <devices.txt> -u <user> -p <pass> [-l log] [-o outdir]

Options:
  -h, --host    Single device IP or hostname
  -f, --file    File containing device list (one per line)
  -u, --user    SSH username
  -p, --pass    SSH password (and enable password if needed)
  -l, --log     Append log output to this file
  -o, --outdir  Output directory for config files (default: ./configs)
USAGE
    exit 1;
}
```