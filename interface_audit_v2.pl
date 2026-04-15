```perl
#!/usr/bin/perl
# =============================================================================
# port_security_audit.pl - Cisco IOS Port Security Audit Tool
# =============================================================================
# Purpose:
#   Connects to Cisco IOS/IOS-XE devices via SSH and audits port security
#   configurations. Reports violation counts, sticky MACs, max MAC limits,
#   and flags ports in error-disabled state due to security violations.
#
# Usage:
#   ./port_security_audit.pl -h <host> [-u <user>] [-p <pass>] [-l <logfile>]
#   ./port_security_audit.pl -f <device_list.txt> [-u <user>] [-p <pass>] [-l <logfile>]
#
# Prerequisites:
#   cpan Net::SSH::Expect Getopt::Long
#
# Device list file format (one host per line, blank lines and # comments ok):
#   192.168.1.1
#   switch02.corp.example.com
#
# Exit codes: 0=success, 1=arg error, 2=connection failure, 3=auth failure
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_logfile, $opt_help);
$opt_user = $ENV{NET_USER} // 'admin';
$opt_pass = $ENV{NET_PASS} // '';

GetOptions(
    'h|host=s'    => \$opt_host,
    'f|file=s'    => \$opt_file,
    'u|user=s'    => \$opt_user,
    'p|pass=s'    => \$opt_pass,
    'l|log=s'     => \$opt_logfile,
    'help'        => \$opt_help,
) or usage();

usage() if $opt_help;
usage() unless $opt_host || $opt_file;

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} elsif ($opt_file) {
    open my $fh, '<', $opt_file or die "Cannot open $opt_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^\s*#/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($opt_logfile) {
    open $log_fh, '>>', $opt_logfile or warn "Cannot open log $opt_logfile: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("=" x 70);
output("Port Security Audit - $timestamp");
output("=" x 70);

for my $host (@devices) {
    audit_device($host);
}

close $log_fh if $log_fh;
exit 0;

# -----------------------------------------------------------------------------
sub audit_device {
    my ($host) = @_;
    output("\n--- Device: $host ---");

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $opt_user,
        password    => $opt_pass,
        ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
        raw_pty     => 1,
        timeout     => 15,
    );

    my $login_output;
    eval { $login_output = $ssh->login() };
    if ($@) {
        output("  ERROR: Connection failed to $host - $@");
        return;
    }
    if ($login_output =~ /[Pp]assword|[Aa]uthentication failed/i && $login_output !~ /[>#]/) {
        output("  ERROR: Authentication failed for $host");
        return;
    }

    # Disable paging
    $ssh->send("terminal length 0");
    $ssh->waitfor('[>#]', 5);

    # Collect port security summary
    $ssh->send("show port-security");
    my $ps_output = $ssh->waitfor('[>#]', 20) // '';

    # Collect interface detail for error-disabled
    $ssh->send("show interfaces status err-disabled");
    my $errdis_output = $ssh->waitfor('[>#]', 20) // '';

    # Collect sticky MAC detail
    $ssh->send("show port-security address");
    my $mac_output = $ssh->waitfor('[>#]', 20) // '';

    $ssh->send("exit");

    parse_and_report($host, $ps_output, $errdis_output, $mac_output);
}

# -----------------------------------------------------------------------------
sub parse_and_report {
    my ($host, $ps_out, $errdis_out, $mac_out) = @_;

    my @violations;
    my @errdisabled;
    my $total_secure = 0;
    my $total_ports  = 0;

    # Parse: show port-security
    # Format: Gi1/0/1   Enabled   Restrict   0          1          0
    for my $line (split /\n/, $ps_out) {
        next unless $line =~ /^((?:Gi|Fa|Te|Hu|Et)\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)/i;
        my ($intf, $enabled, $violation_mode, $cur_addr, $max_addr, $violation_count) = ($1,$2,$3,$4,$5,$6);
        next unless lc($enabled) eq 'enabled';
        $total_ports++;
        $total_secure += $cur_addr;
        if ($violation_count > 0) {
            push @violations, sprintf("  %-20s  mode=%-10s  violations=%d  macs=%d/%d",
                $intf, $violation_mode, $violation_count, $cur_addr, $max_addr);
        }
    }

    # Parse: show interfaces status err-disabled
    for my $line (split /\n/, $errdis_out) {
        next unless $line =~ /^((?:Gi|Fa|Te|Hu|Et)\S+)\s+.*psecure-violation/i;
        push @errdisabled, "  $1  [err-disabled: psecure-violation]";
    }

    # Count sticky MACs
    my $sticky_count = () = $mac_out =~ /SecureSticky/gi;

    output(sprintf("  Secure ports : %d", $total_ports));
    output(sprintf("  Secured MACs : %d", $total_secure));
    output(sprintf("  Sticky MACs  : %d", $sticky_count));

    if (@violations) {
        output(sprintf("  Ports with violations (%d):", scalar @violations));
        output($_) for @violations;
    } else {
        output("  No active violation counts detected.");
    }

    if (@errdisabled) {
        output(sprintf("  Err-disabled by port-security (%d):", scalar @errdisabled));
        output($_) for @errdisabled;
    } else {
        output("  No interfaces err-disabled by port-security.");
    }
}

# -----------------------------------------------------------------------------
sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}

sub usage {
    print <<'USAGE';
Usage: port_security_audit.pl -h <host> | -f <file> [-u user] [-p pass] [-l logfile]

  -h, --host   Single device IP or hostname
  -f, --file   File containing list of devices (one per line)
  -u, --user   SSH username (default: $NET_USER env or 'admin')
  -p, --pass   SSH password (default: $NET_PASS env)
  -l, --log    Append output to log file
  --help       This help message

USAGE
    exit 1;
}
```