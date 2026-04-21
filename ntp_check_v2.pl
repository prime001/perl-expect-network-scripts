```perl
#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# ntp_drift_audit.pl — NTP Stratum & Drift Compliance Auditor
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices and audits NTP health beyond basic
#   reachability: verifies stratum level, clock offset drift, reference source,
#   and flags devices that exceed acceptable drift thresholds or are orphaned
#   (stratum 16 / unsynchronized).
#
# Usage:
#   Single device:  perl ntp_drift_audit.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    perl ntp_drift_audit.pl -f devices.txt -u admin -p secret
#   With log:       perl ntp_drift_audit.pl -f devices.txt -u admin -p secret -l audit.log
#   Custom limits:  perl ntp_drift_audit.pl -h 10.0.0.1 -u admin -p secret --max-stratum 3 --max-offset 500
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH access to devices; 'terminal length 0' supported
#
# Device file format: one IP/hostname per line, blank lines and # comments OK
# =============================================================================

my ($host, $user, $pass, $device_file, $log_file);
my $max_stratum = 4;
my $max_offset  = 1000;   # milliseconds

GetOptions(
    'h|host=s'        => \$host,
    'u|user=s'        => \$user,
    'p|pass=s'        => \$pass,
    'f|file=s'        => \$device_file,
    'l|log=s'         => \$log_file,
    'max-stratum=i'   => \$max_stratum,
    'max-offset=f'    => \$max_offset,
) or die "Error parsing arguments. Use -h, -u, -p, and optionally -f/-l.\n";

die "Must supply username (-u) and password (-p)\n" unless $user && $pass;
die "Must supply -h <host> or -f <file>\n" unless $host || $device_file;

my @devices;
if ($host) {
    push @devices, $host;
}
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+//; s/\s+$//;
        push @devices, $_ if $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=" x 70);
output("NTP Drift Compliance Audit  —  $ts");
output("Thresholds: max stratum=$max_stratum  max offset=${max_offset}ms");
output("=" x 70);

my ($pass_count, $fail_count) = (0, 0);

for my $dev (@devices) {
    output("\n[ Device: $dev ]");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $dev,
            user        => $user,
            password    => $pass,
            raw_pty     => 1,
            timeout     => 15,
        );
    };
    if ($@ || !$ssh) {
        output("  ERROR: Could not create SSH object — $@");
        $fail_count++;
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !$login) {
        output("  ERROR: Authentication failed or connection refused");
        $fail_count++;
        next;
    }

    $ssh->exec("terminal length 0");

    # --- show ntp status ---
    my $ntp_status = $ssh->exec("show ntp status");
    my ($stratum, $ref_source, $offset, $sync_state) = ('?', '?', '?', 'unknown');

    if ($ntp_status =~ /Clock is (\w+)/i) {
        $sync_state = lc($1);   # synchronized / unsynchronized
    }
    if ($ntp_status =~ /stratum\s+(\d+)/i) {
        $stratum = $1;
    }
    if ($ntp_status =~ /reference is\s+([\d\.a-fA-F:]+)/i) {
        $ref_source = $1;
    }
    if ($ntp_status =~ /offset\s+([\-\d\.]+)/i) {
        $offset = $1;
    }

    output("  Sync state : $sync_state");
    output("  Stratum    : $stratum");
    output("  Reference  : $ref_source");
    output("  Offset     : ${offset}ms");

    # --- compliance checks ---
    my @violations;
    push @violations, "UNSYNCHRONIZED (stratum 16 / free-running)"
        if $sync_state ne 'synchronized';
    push @violations, "Stratum $stratum exceeds max allowed ($max_stratum)"
        if $stratum =~ /^\d+$/ && $stratum > $max_stratum;
    push @violations, "Offset ${offset}ms exceeds threshold (${max_offset}ms)"
        if $offset =~ /^[\-\d\.]+$/ && abs($offset) > $max_offset;

    if (@violations) {
        output("  STATUS     : FAIL");
        output("  VIOLATIONS :");
        output("    - $_") for @violations;
        $fail_count++;
    } else {
        output("  STATUS     : PASS");
        $pass_count++;
    }

    $ssh->close();
}

output("\n" . "=" x 70);
output("SUMMARY: " . scalar(@devices) . " devices — PASS=$pass_count  FAIL=$fail_count");
output("=" x 70);

close $log_fh if $log_fh;
exit($fail_count ? 1 : 0);

sub output {
    my ($line) = @_;
    print "$line\n";
    print $log_fh "$line\n" if $log_fh;
}
```