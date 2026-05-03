#!/usr/bin/perl
#
# interface_utilization_audit.pl
#
# PURPOSE: Audits interface utilization and error counters on Cisco IOS/IOS-XE
#          devices. Flags overutilized links and interfaces with elevated CRC,
#          input error, or output drop rates that indicate hardware faults or
#          duplex mismatches. Complements interface_audit_v2.pl (status/config)
#          with real-time traffic and error-rate data.
#
# USAGE:   ./interface_utilization_audit.pl --host 10.0.0.1 --user admin --pass s3cr3t
#          ./interface_utilization_audit.pl --file devices.txt --user admin --pass s3cr3t \
#                                           --enable en_pass --log audit.log --threshold 80
#
# PREREQS: Net::SSH::Expect  (cpan install Net::SSH::Expect)
#          SSH enabled on target device; read-only (priv-1) credentials sufficient.
#          Tested on Cisco IOS 12.4+, IOS-XE 16.x/17.x.
#
# OUTPUT:  Columnar utilization report to STDOUT; appended to --log if specified.

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $enable_pass, $log_file);
my $threshold = 70;

GetOptions(
    'host=s'      => \$host,
    'file=s'      => \$device_file,
    'user=s'      => \$username,
    'pass=s'      => \$password,
    'enable=s'    => \$enable_pass,
    'log=s'       => \$log_file,
    'threshold=i' => \$threshold,
) or die usage();

die usage() unless ($host || $device_file) && $username && $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $device_file or die "Cannot open '$device_file': $!\n";
    while (<$fh>) { chomp; next if /^\s*[#;]/ || /^\s*$/; push @devices, $_; }
    close $fh;
}

my $LOG;
if ($log_file) {
    open $LOG, '>>', $log_file or die "Cannot open log '$log_file': $!\n";
    printf $LOG "\n=== Interface Utilization Audit: %s ===\n", strftime("%Y-%m-%d %H:%M:%S", localtime);
}

audit_device($_) for @devices;
close $LOG if $LOG;

sub audit_device {
    my ($dev) = @_;
    my $ssh = Net::SSH::Expect->new(
        host     => $dev,
        user     => $username,
        password => $password,
        raw_pty  => 1,
        timeout  => 15,
    );

    my $login;
    eval { $login = $ssh->login() };
    if ($@ || $login =~ /password|denied/i) {
        warn "[$dev] Connection/auth failed: " . ($@ // "bad credentials") . "\n";
        return;
    }

    if ($enable_pass) {
        $ssh->send("enable");
        $ssh->waitfor('Password:', 5) or warn "[$dev] No enable prompt\n";
        $ssh->send($enable_pass);
        $ssh->waitfor('#', 5)         or warn "[$dev] Enable mode failed\n";
    }

    $ssh->exec("terminal length 0");

    my $hostname = $dev;
    my $ver = $ssh->exec("show version | include uptime");
    $hostname = $1 if $ver =~ /^(\S+)\s+uptime/m;

    my $raw = $ssh->exec("show interfaces");
    $ssh->close();

    my @ifaces = parse_interfaces($raw);

    my $hdr = sprintf "\n[%s] Interface Utilization (threshold: %d%%)\n%-22s %-6s %-12s %-12s %-8s %-8s %-8s %s\n%s\n",
        $hostname, $threshold,
        "Interface", "Status", "In Rate", "Out Rate", "InErr", "CRC", "OutDrop", "Flags",
        "-" x 88;
    out($hdr);

    for my $i (@ifaces) {
        my $flags = join ' ', grep { $_ }
            ($i->{in_pct} >= $threshold || $i->{out_pct} >= $threshold) ? 'UTIL'  : '',
            $i->{in_errors} > 0                                         ? 'INERR' : '',
            $i->{crc}       > 0                                         ? 'CRC'   : '',
            $i->{out_drops} > 0                                         ? 'DROPS' : '';
        out(sprintf "%-22s %-6s %-12s %-12s %-8d %-8d %-8d %s\n",
            $i->{name}, $i->{status},
            fmt_rate($i->{in_rate}), fmt_rate($i->{out_rate}),
            $i->{in_errors}, $i->{crc}, $i->{out_drops}, $flags);
    }
}

sub parse_interfaces {
    my ($raw) = @_;
    my (@result, %cur);
    for my $line (split /\n/, $raw) {
        if ($line =~ /^(\S+) is (up|down|administratively down)/) {
            push @result, {%cur} if $cur{name};
            %cur = (name => $1, status => ($2 eq 'up' ? 'up' : 'down'),
                    in_rate => 0, out_rate => 0, bandwidth => 0,
                    in_pct => 0, out_pct => 0, in_errors => 0, crc => 0, out_drops => 0);
        }
        $cur{bandwidth}  = $1 * 1000 if $line =~ /BW (\d+) Kbit/;
        if ($line =~ /input rate (\d+) bits/) {
            $cur{in_rate} = $1;
            $cur{in_pct}  = $cur{bandwidth} ? int($1 / $cur{bandwidth} * 100) : 0;
        }
        if ($line =~ /output rate (\d+) bits/) {
            $cur{out_rate} = $1;
            $cur{out_pct}  = $cur{bandwidth} ? int($1 / $cur{bandwidth} * 100) : 0;
        }
        $cur{in_errors} = $1 if $line =~ /(\d+) input errors/;
        $cur{crc}       = $1 if $line =~ /(\d+) CRC/;
        $cur{out_drops} = $1 if $line =~ /(\d+) output drops/;
    }
    push @result, {%cur} if $cur{name};
    return grep { $_->{status} eq 'up' } @result;
}

sub fmt_rate {
    my ($b) = @_;
    return '0 bps'                          if $b == 0;
    return sprintf "%.1f Kbps", $b / 1e3   if $b < 1e6;
    return sprintf "%.1f Mbps", $b / 1e6   if $b < 1e9;
    return sprintf "%.1f Gbps", $b / 1e9;
}

sub out {
    print $_[0];
    print $LOG $_[0] if $LOG;
}

sub usage { "Usage: $0 --host <ip> | --file <file> --user <u> --pass <p> [--enable <p>] [--log <f>] [--threshold <pct>]\n" }