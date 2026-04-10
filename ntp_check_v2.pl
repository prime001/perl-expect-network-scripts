```perl
#!/usr/bin/perl
# =============================================================================
# ntp_check_v2.pl - Enhanced NTP Stratum & Drift Analysis Tool
# =============================================================================
# Purpose:
#   Connects to one or more Cisco IOS/IOS-XE devices via SSH and performs
#   detailed NTP health analysis: stratum validation, clock drift, offset
#   thresholds, and peer comparison across a fleet. Flags devices with
#   excessive drift, high stratum, or no sync.
#
# Usage:
#   Single device:  ./ntp_check_v2.pl -h 192.168.1.1 [-u admin] [-p pass]
#   Device file:    ./ntp_check_v2.pl -f devices.txt [-u admin] [-p pass]
#   With log:       ./ntp_check_v2.pl -f devices.txt -l ntp_report.log
#
# Device file format (one per line, optionally tab-separated host:user:pass):
#   192.168.1.1
#   192.168.1.2  netadmin  s3cr3t
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH key auth recommended; passwords via CLI prompt if not in device file
#
# Exit codes: 0=all OK, 1=warnings, 2=critical failures
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);
use Term::ReadKey qw(ReadMode ReadLine);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_log);
my $TIMEOUT       = 20;
my $MAX_OFFSET_MS = 500;   # warn if NTP offset > 500ms
my $MAX_STRATUM   = 5;     # warn if stratum > 5
my $exit_code     = 0;

GetOptions(
    'h|host=s'     => \$opt_host,
    'f|file=s'     => \$opt_file,
    'u|user=s'     => \$opt_user,
    'p|pass=s'     => \$opt_pass,
    'l|log=s'      => \$opt_log,
) or die "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile]\n";

die "Specify -h <host> or -f <file>\n" unless $opt_host || $opt_file;

$opt_user //= $ENV{NET_USER} // 'admin';

unless ($opt_pass) {
    print "Password: ";
    ReadMode('noecho');
    chomp($opt_pass = ReadLine(0));
    ReadMode('restore');
    print "\n";
}

my $LOG;
if ($opt_log) {
    open($LOG, '>>', $opt_log) or die "Cannot open log $opt_log: $!";
    $LOG->autoflush(1);
}

sub log_out {
    my ($msg) = @_;
    my $ts = strftime("[%Y-%m-%d %H:%M:%S]", localtime);
    print "$ts $msg\n";
    print $LOG "$ts $msg\n" if $LOG;
}

sub load_devices {
    my @devs;
    if ($opt_host) {
        push @devs, { host => $opt_host, user => $opt_user, pass => $opt_pass };
    } else {
        open(my $fh, '<', $opt_file) or die "Cannot open $opt_file: $!";
        while (<$fh>) {
            chomp; s/^\s+|\s+$//g; next if /^#/ || /^$/;
            my ($h, $u, $p) = split /[\t,]+/;
            push @devs, {
                host => $h,
                user => $u // $opt_user,
                pass => $p // $opt_pass,
            };
        }
        close $fh;
    }
    return @devs;
}

sub check_device {
    my ($dev) = @_;
    my $host = $dev->{host};

    log_out("[$host] Connecting...");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $dev->{user},
        password    => $dev->{pass},
        raw_pty     => 1,
        timeout     => $TIMEOUT,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    my $login;
    eval { $login = $ssh->login() };
    if ($@ || !defined $login) {
        log_out("[$host] ERROR: Connection/auth failed - $@");
        return 2;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$|#', 5);

    # Collect NTP status
    $ssh->send("show ntp status\n");
    my $ntp_status = $ssh->waitfor('\$|#', $TIMEOUT) // '';

    $ssh->send("show ntp associations detail\n");
    my $ntp_detail = $ssh->waitfor('\$|#', $TIMEOUT) // '';

    $ssh->send("show clock detail\n");
    my $clock_out = $ssh->waitfor('\$|#', $TIMEOUT) // '';

    $ssh->close();

    # --- Parse NTP status ---
    my $synced   = ($ntp_status =~ /Clock is synchronized/i) ? 1 : 0;
    my $stratum  = ($ntp_status =~ /stratum\s+(\d+)/i)       ? $1 : 'N/A';
    my $ref_ip   = ($ntp_status =~ /reference is\s+([\d.]+)/i) ? $1 : 'unknown';
    my $offset   = ($ntp_status =~ /offset\s+is\s+([\d.-]+)\s+msec/i) ? $1 : undef;
    my $freq_err = ($ntp_status =~ /frequency\s+error\s+is\s+([\d.-]+)\s+ppm/i) ? $1 : undef;

    # --- Parse clock source ---
    my $auth_ntp = ($clock_out =~ /NTP synchronized/i) ? 'NTP' :
                   ($clock_out =~ /\.authoritative/i)   ? 'authoritative' : 'unknown';

    my $dev_status = 0;

    if (!$synced) {
        log_out("[$host] CRITICAL: NTP NOT synchronized");
        $dev_status = 2;
    } else {
        log_out("[$host] OK: Synchronized to $ref_ip (stratum $stratum)");

        if ($stratum ne 'N/A' && $stratum > $MAX_STRATUM) {
            log_out("[$host] WARNING: High stratum $stratum (threshold: $MAX_STRATUM)");
            $dev_status = 1 if $dev_status < 1;
        }

        if (defined $offset && abs($offset) > $MAX_OFFSET_MS) {
            log_out("[$host] WARNING: Offset ${offset}ms exceeds threshold ${MAX_OFFSET_MS}ms");
            $dev_status = 1 if $dev_status < 1;
        } elsif (defined $offset) {
            log_out("[$host] Offset: ${offset}ms  Freq error: " . ($freq_err // 'N/A') . " ppm");
        }
    }

    # Count reachable vs unreachable peers
    my @peers = ($ntp_detail =~ /address:\s+([\d.]+)/gi);
    my @reach  = ($ntp_detail =~ /reachability=(\d+)/gi);
    my $reach_count = grep { $_ > 0 } @reach;
    log_out("[$host] Peers: " . scalar(@peers) . " configured, $reach_count reachable");

    if (@peers && $reach_count == 0) {
        log_out("[$host] CRITICAL: No NTP peers are reachable");
        $dev_status = 2;
    } elsif (@peers && $reach_count < scalar(@peers)) {
        log_out("[$host] WARNING: " . (scalar(@peers) - $reach_count) . " peer(s) unreachable");
        $dev_status = 1 if $dev_status < 1;
    }

    return $dev_status;
}

# --- Main ---
log_out("NTP stratum/drift analysis starting");
log_out("Thresholds: offset>${MAX_OFFSET_MS}ms = WARN, stratum>${MAX_STRATUM} = WARN");

my @devices = load_devices();
log_out("Loaded " . scalar(@devices) . " device(s)");

for my $dev (@devices) {
    my $rc = check_device($dev);
    $exit_code = $rc if $rc > $exit_code;
}

my $summary = $exit_code == 0 ? 'ALL OK'
            : $exit_code == 1 ? 'WARNINGS present'
            : 'CRITICAL failures';
log_out("Done. Status: $summary");

close $LOG if $LOG;
exit $exit_code;
```