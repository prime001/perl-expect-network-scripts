The perl-expect-network-scripts repo isn't on this machine — the user wants the script content as output. Writing it now.

#!/usr/bin/perl
#
# ntp_compliance_audit.pl - NTP Policy Compliance Audit for Cisco IOS/IOS-XE
#
# Purpose:
#   Connects to one or more network devices via SSH and audits NTP compliance
#   against a defined policy: maximum allowed stratum level, acceptable clock
#   offset threshold (ms), and optionally an approved NTP server whitelist.
#   Flags any device that is unsynchronized, exceeds drift thresholds, uses an
#   unauthorized reference, or cannot be reached. Distinct from ntp_check.pl /
#   ntp_check_v2.pl, which verify NTP is configured — this script enforces a
#   site-wide NTP security and accuracy policy across a fleet.
#
# Usage:
#   Single device:  perl ntp_compliance_audit.pl -h 10.0.0.1 -u admin -p secret
#   Device list:    perl ntp_compliance_audit.pl -f devices.txt -u admin -p secret
#   With log:       perl ntp_compliance_audit.pl -f devices.txt -u admin -p secret -l audit.log
#   Full policy:    perl ntp_compliance_audit.pl -f devices.txt -u admin -p secret \
#                     -s 3 -d 200 --servers 10.0.0.5,10.0.0.6
#
# Options:
#   -h <host>        Single device IP or hostname
#   -f <file>        File with one device per line (# = comment)
#   -u <user>        SSH username
#   -p <pass>        SSH password
#   -e <pass>        Enable password (defaults to SSH password)
#   -l <file>        Log file path (optional)
#   -s <n>           Max allowed stratum (default: 3)
#   -d <ms>          Max allowed clock offset in ms (default: 500)
#   --servers <csv>  Comma-separated approved NTP server IPs (optional)
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   cpan Getopt::Long   (usually bundled)
#
# Exit codes:  0 = all compliant,  1 = one or more non-compliant or unreachable
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($opt_host, $opt_file, $username, $password, $enable_pass, $log_file);
my $max_stratum      = 3;
my $max_offset_ms    = 500;
my $approved_csv     = '';

GetOptions(
    'h=s'       => \$opt_host,
    'f=s'       => \$opt_file,
    'u=s'       => \$username,
    'p=s'       => \$password,
    'e=s'       => \$enable_pass,
    'l=s'       => \$log_file,
    's=i'       => \$max_stratum,
    'd=f'       => \$max_offset_ms,
    'servers=s' => \$approved_csv,
) or die "Option error. See script header for usage.\n";

die "Username required (-u)\n"               unless $username;
die "Password required (-p)\n"               unless $password;
die "Specify -h <host> or -f <file>\n"       unless $opt_host || $opt_file;

$enable_pass //= $password;
my @approved = $approved_csv ? split /,/, $approved_csv : ();

my @devices;
push @devices, $opt_host if $opt_host;
if ($opt_file) {
    open my $fh, '<', $opt_file or die "Cannot open '$opt_file': $!\n";
    while (<$fh>) { chomp; s/#.*//; s/^\s+|\s+$//g; push @devices, $_ if $_ }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>', $log_file or die "Cannot open log '$log_file': $!\n";
}

sub out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("NTP Compliance Audit  $ts\n");
out("Policy: stratum<=$max_stratum  offset<=${max_offset_ms}ms");
out(@approved ? "  servers=" . join(',', @approved) : "  servers=any");
out("\n" . "=" x 68 . "\n\n");

my $fail_count = 0;

for my $dev (@devices) {
    out("[$dev]\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host       => $dev,
            user       => $username,
            password   => $password,
            raw_pty    => 1,
            timeout    => 15,
            ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
    };
    if ($@ || !$ssh || !eval { $ssh->login() }) {
        out("  RESULT: UNREACHABLE - " . ($@ // 'login failed') . "\n\n");
        $fail_count++;
        next;
    }

    $ssh->exec("terminal length 0");
    my $prompt = $ssh->exec("") // '';
    if ($prompt =~ />\s*$/) {
        $ssh->send("enable");
        my $r = $ssh->waitfor('Password:|#', 5);
        if ($r && $r =~ /Password:/) {
            $ssh->send($enable_pass);
            $ssh->waitfor('#', 5);
        }
    }

    my $status_out = $ssh->exec("show ntp status")              // '';
    my $assoc_out  = $ssh->exec("show ntp associations detail")  // '';
    $ssh->close();

    my @issues;

    my $synced = ($status_out =~ /Clock is synchronized/i);
    push @issues, 'clock not synchronized' unless $synced;

    my ($stratum) = ($status_out =~ /stratum\s+(\d+)/i);
    if (defined $stratum) {
        out(sprintf("  stratum  : %d\n", $stratum));
        push @issues, "stratum $stratum > policy $max_stratum" if $stratum > $max_stratum;
    } else {
        push @issues, 'stratum not parseable';
    }

    my ($offset) = ($status_out =~ /offset\s+([-\d.]+)\s+msec/i);
    if (defined $offset) {
        out(sprintf("  offset   : %s ms\n", $offset));
        push @issues, sprintf("offset %.1fms > policy %.0fms", abs($offset), $max_offset_ms)
            if abs($offset) > $max_offset_ms;
    } else {
        push @issues, 'offset not parseable';
    }

    my ($ref) = ($status_out =~ /reference is\s+([\d.]+)/i);
    ($ref)    = ($assoc_out  =~ /our mode client.*?\nref ID\s+([\d.]+)/si) unless $ref;
    if ($ref) {
        out("  reference: $ref\n");
        if (@approved && !grep { $_ eq $ref } @approved) {
            push @issues, "reference $ref not in approved list";
        }
    } else {
        out("  reference: (unknown)\n");
    }

    if (@issues) {
        out("  RESULT: NON-COMPLIANT\n");
        out("    - $_\n") for @issues;
        $fail_count++;
    } else {
        out("  RESULT: COMPLIANT\n");
    }
    out("\n");
}

out("=" x 68 . "\n");
out(sprintf("AUDIT COMPLETE: %d device(s), %d non-compliant\n",
    scalar(@devices), $fail_count));

close $log_fh if $log_fh;
exit($fail_count ? 1 : 0);