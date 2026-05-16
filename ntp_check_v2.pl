The task says "Output ONLY the script content" — here it is:

#!/usr/bin/perl
# =============================================================================
# ntp_compliance_audit.pl — NTP Configuration Compliance Auditor
# =============================================================================
# Purpose:
#   Audits NTP policy compliance across Cisco IOS/IOS-XE devices. Unlike
#   ntp_check.pl (which reports status), this script enforces a defined
#   baseline: required NTP servers, maximum stratum, authentication config,
#   and access-group hardening. Designed for compliance sweeps before audits
#   or after provisioning new network segments.
#
# Usage:
#   ./ntp_compliance_audit.pl -d <device_file> -u <username> -p <password>
#                             [-s <srv1,srv2>] [-m <max_stratum>]
#                             [-l <logfile>] [-v]
#
#   -d  File with one device IP/hostname per line (# lines are comments)
#   -u  SSH username
#   -p  SSH password
#   -s  Comma-separated list of required NTP servers (baseline policy)
#   -m  Maximum acceptable stratum level (default: 5)
#   -l  Log file path (default: ntp_compliance_YYYYMMDD_HHMMSS.log)
#   -v  Verbose per-check output
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH access with exec privilege sufficient; enable not required
#
# Example:
#   ./ntp_compliance_audit.pl -d core_switches.txt -u netadmin -p s3cr3t \
#       -s 10.0.1.10,10.0.1.11 -m 4 -l audit_$(date +%F).log -v
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($device_file, $username, $password, $servers_arg, $max_stratum, $logfile, $verbose);

GetOptions(
    'd=s' => \$device_file,
    'u=s' => \$username,
    'p=s' => \$password,
    's=s' => \$servers_arg,
    'm=i' => \$max_stratum,
    'l=s' => \$logfile,
    'v'   => \$verbose,
) or die "Usage: $0 -d <file> -u <user> -p <pass> [-s srv1,srv2] [-m max_stratum] [-l log] [-v]\n";

die "ERROR: -d device_file required\n"   unless $device_file;
die "ERROR: -u username required\n"      unless $username;
die "ERROR: -p password required\n"      unless $password;
die "ERROR: $device_file not found\n"    unless -f $device_file;

$max_stratum //= 5;
my $ts_start  = strftime("%Y%m%d_%H%M%S", localtime);
$logfile    //= "ntp_compliance_${ts_start}.log";

my @required_servers = $servers_arg ? split(/,/, $servers_arg) : ();

open(my $log, '>', $logfile) or die "Cannot open log '$logfile': $!\n";

sub emit {
    my ($msg) = @_;
    my $ts = strftime("[%H:%M:%S]", localtime);
    print "$ts $msg\n";
    print $log "$ts $msg\n";
}

sub audit_device {
    my ($host) = @_;
    emit("Connecting: $host");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host       => $host,
            user       => $username,
            password    => $password,
            raw_pty    => 1,
            timeout    => 15,
            ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        );
        $ssh->login();
    };
    if ($@) {
        my $err = $@; $err =~ s/\n/ /g;
        emit("  UNREACHABLE: $host — $err");
        return { host => $host, status => 'UNREACHABLE', issues => [] };
    }

    my @issues;
    $ssh->exec("terminal length 0");

    my $ntp_status = $ssh->exec("show ntp status")          // '';
    my $ntp_assoc  = $ssh->exec("show ntp associations")    // '';
    my $ntp_cfg    = $ssh->exec("show run | include ^ntp")  // '';

    $ssh->close();

    # Sync state
    if ($ntp_status !~ /Clock is synchronized/i) {
        push @issues, "NTP not synchronized";
        emit("  FAIL  [$host] NTP not synchronized") if $verbose;
    } else {
        emit("  OK    [$host] NTP synchronized") if $verbose;
    }

    # Stratum threshold
    if ($ntp_status =~ /stratum\s+(\d+)/i) {
        my $stratum = $1;
        if ($stratum > $max_stratum) {
            push @issues, "Stratum $stratum exceeds policy max ($max_stratum)";
            emit("  FAIL  [$host] Stratum $stratum > $max_stratum") if $verbose;
        } else {
            emit("  OK    [$host] Stratum $stratum") if $verbose;
        }
    } else {
        push @issues, "Unable to determine stratum from 'show ntp status'";
    }

    # Required NTP servers
    for my $srv (@required_servers) {
        my $in_cfg   = $ntp_cfg   =~ /ntp\s+server\s+\Q$srv\E/i;
        my $in_assoc = $ntp_assoc =~ /\Q$srv\E/;
        if (!$in_cfg && !$in_assoc) {
            push @issues, "Required NTP server $srv not configured";
            emit("  FAIL  [$host] Missing required server $srv") if $verbose;
        } else {
            emit("  OK    [$host] Required server $srv present") if $verbose;
        }
    }

    # NTP authentication consistency
    my $auth_enabled = $ntp_cfg =~ /ntp\s+authenticate\b/i;
    my $auth_keys    = $ntp_cfg =~ /ntp\s+authentication-key/i;
    my $trusted_key  = $ntp_cfg =~ /ntp\s+trusted-key/i;
    if ($auth_enabled && (!$auth_keys || !$trusted_key)) {
        push @issues, "NTP authenticate enabled but authentication-key/trusted-key incomplete";
        emit("  FAIL  [$host] NTP auth config incomplete") if $verbose;
    } elsif (!$auth_enabled) {
        push @issues, "NTP authentication not enabled (policy requirement)";
        emit("  WARN  [$host] NTP authentication disabled") if $verbose;
    } else {
        emit("  OK    [$host] NTP authentication configured") if $verbose;
    }

    # Access-group hardening
    if ($ntp_cfg !~ /ntp\s+access-group/i) {
        push @issues, "No ntp access-group configured (restricts NTP query/serve exposure)";
        emit("  WARN  [$host] No NTP access-group") if $verbose;
    } else {
        emit("  OK    [$host] NTP access-group present") if $verbose;
    }

    my $status = @issues ? 'FAIL' : 'PASS';
    emit("  RESULT [$host] $status" . (@issues ? " (" . scalar(@issues) . " issue(s))" : ''));
    return { host => $host, status => $status, issues => \@issues };
}

# Load device list
open(my $fh, '<', $device_file) or die "Cannot open '$device_file': $!\n";
my @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
close($fh);

emit("NTP Compliance Audit — " . scalar(@devices) . " devices");
emit("Policy: max_stratum=$max_stratum, required_servers=" .
     (@required_servers ? join(',', @required_servers) : '(none)'));
emit("-" x 60);

my (@pass, @fail, @unreachable);
for my $host (@devices) {
    my $r = audit_device($host);
    if    ($r->{status} eq 'PASS')        { push @pass, $host }
    elsif ($r->{status} eq 'UNREACHABLE') { push @unreachable, $host }
    else {
        push @fail, $host;
        emit("    ! $_") for @{$r->{issues}};
    }
}

emit("=" x 60);
emit(sprintf("SUMMARY: %d PASS  %d FAIL  %d UNREACHABLE  (of %d)",
    scalar @pass, scalar @fail, scalar @unreachable, scalar @devices));
emit("Failed:      " . join(', ', @fail))        if @fail;
emit("Unreachable: " . join(', ', @unreachable)) if @unreachable;
emit("Log: $logfile");
close($log);

exit(@fail || @unreachable ? 1 : 0);