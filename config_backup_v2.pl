```perl
#!/usr/bin/perl
# config_compliance.pl - Cisco IOS/IOS-XE Configuration Compliance Auditor
#
# PURPOSE: Connects to one or more network devices via SSH, retrieves the running
#          configuration, and evaluates it against a policy checklist covering
#          security hardening, AAA, logging, and management-plane settings.
#          Generates a per-device compliance score suitable for audit reporting.
#
# USAGE:
#   Single device:  perl config_compliance.pl -h 10.0.0.1 -u admin -p secret
#   From file:      perl config_compliance.pl -f devices.txt -u admin -p secret -l audit.log
#   Env creds:      NET_USER=admin NET_PASS=secret perl config_compliance.pl -h 10.0.0.1
#
# DEVICE FILE FORMAT: one IP/hostname per line; lines starting with # are skipped
#
# PREREQUISITES:
#   cpanm Net::SSH::Expect Getopt::Long
#   SSH access with at least 'show running-config' privilege on each device
#   Tested against Cisco IOS 15.x, IOS-XE 16.x, NX-OS 9.x

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($opt_host, $opt_user, $opt_pass, $opt_file, $opt_log);
my $opt_timeout = 30;

GetOptions(
    'h|host=s'    => \$opt_host,
    'u|user=s'    => \$opt_user,
    'p|pass=s'    => \$opt_pass,
    'f|file=s'    => \$opt_file,
    'l|log=s'     => \$opt_log,
    't|timeout=i' => \$opt_timeout,
) or usage();

$opt_user //= $ENV{NET_USER} // 'admin';
$opt_pass //= $ENV{NET_PASS} or die "ERROR: Password required via -p or NET_PASS env var\n";

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} elsif ($opt_file) {
    open my $fh, '<', $opt_file or die "Cannot open device file '$opt_file': $!\n";
    while (<$fh>) { chomp; push @devices, $_ unless /^\s*#|^\s*$/ }
    close $fh;
} else {
    usage();
}

my $log_fh;
if ($opt_log) {
    open $log_fh, '>>', $opt_log or warn "WARN: Cannot open log '$opt_log': $! — logging to STDOUT only\n";
}

# Policy checks: each value is a regex (must match) or coderef returning 1=pass
my %POLICY = (
    'AAA new-model enabled'          => qr/^aaa new-model/m,
    'Service password-encryption'    => qr/^service password-encryption/m,
    'SSH v2 enforced'                => qr/^ip ssh version 2/m,
    'Telnet transport blocked'       => sub { $_[0] !~ /transport input.*telnet/m },
    'HTTP server disabled'           => sub { $_[0] !~ /^ip http server\b/m },
    'HTTPS-only management'          => qr/^ip http secure-server/m,
    'Logging host configured'        => qr/^logging \d+\.\d+\.\d+\.\d+/m,
    'Timestamps on logs/debug'       => qr/^service timestamps (log|debug)/m,
    'NTP server configured'          => qr/^ntp server/m,
    'MOTD or login banner present'   => qr/^banner (motd|login)/m,
    'IP source-route disabled'       => sub { $_[0] !~ /^ip source-route\b/m },
    'IP directed-broadcast disabled' => sub { $_[0] !~ /ip directed-broadcast\b/m },
    'No SNMP v1/v2 community'        => sub { $_[0] !~ /^snmp-server community \S+ (RO|RW)\b/m },
    'Enable secret set'              => qr/^enable secret /m,
);

my ($fleet_pass, $fleet_fail) = (0, 0);
my $stamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
emit("=" x 64);
emit("Config Compliance Audit  —  $stamp");
emit("=" x 64);

for my $device (@devices) {
    emit("\n[ $device ]");

    my $config = pull_config($device);
    unless (defined $config) {
        $fleet_fail += scalar keys %POLICY;
        next;
    }

    my ($pass, $fail) = (0, 0);
    for my $check (sort keys %POLICY) {
        my $ok = ref($POLICY{$check}) eq 'CODE'
            ? $POLICY{$check}->($config)
            : ($config =~ $POLICY{$check});
        printf { \*STDOUT } "  %-44s [%s]\n", $check, $ok ? 'PASS' : 'FAIL';
        print $log_fh sprintf("  %-44s [%s]\n", $check, $ok ? 'PASS' : 'FAIL') if $log_fh;
        $ok ? $pass++ : $fail++;
    }

    my $score = int(100 * $pass / ($pass + $fail || 1));
    emit(sprintf("  Score: %d%%  (%d passed, %d failed)", $score, $pass, $fail));
    $fleet_pass += $pass;
    $fleet_fail += $fail;
}

if (@devices > 1) {
    emit("\n" . "=" x 64);
    my $total = $fleet_pass + $fleet_fail || 1;
    emit(sprintf("Fleet total: %d%% compliant  (%d/%d checks across %d devices)",
        int(100 * $fleet_pass / $total), $fleet_pass, $total, scalar @devices));
}

close $log_fh if $log_fh;
exit(($fleet_fail > 0) ? 1 : 0);

# ------------------------------------------------------------

sub pull_config {
    my ($host) = @_;
    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $opt_user,
        password => $opt_pass,
        raw_pty  => 1,
        timeout  => $opt_timeout,
    );

    my $config;
    eval {
        $ssh->run_ssh() or die "SSH spawn failed\n";

        my $banner = $ssh->waitfor('Password:|>\s*$|#\s*$', $opt_timeout)
            or die "No login prompt received\n";

        # Handle password prompt on banner (some devices)
        if ($banner =~ /Password:/) {
            $ssh->send($opt_pass);
            $ssh->waitfor('>\s*$|#\s*$', $opt_timeout) or die "Auth failed\n";
        }

        # Escalate to enable if we landed at user EXEC prompt
        my $cur = $ssh->get_expect()->after() // '';
        if ($cur =~ />\s*$/ || $banner =~ />\s*$/) {
            $ssh->send('enable');
            my $ep = $ssh->waitfor('Password:|#\s*$', 10) // '';
            if ($ep =~ /Password:/) {
                $ssh->send($opt_pass);
                $ssh->waitfor('#\s*$', 10) or die "Enable auth failed\n";
            }
        }

        $ssh->send('terminal length 0');
        $ssh->waitfor('#\s*$', 10);

        $ssh->send('show running-config');
        $config = $ssh->waitfor('#\s*$', 60) or die "Timeout waiting for config\n";

        $ssh->send('exit');
        $ssh->close();
    };

    if ($@) {
        (my $err = $@) =~ s/\n/ /g;
        emit("  ERROR connecting to $host: $err");
        return undef;
    }

    if (!$config || length($config) < 200) {
        emit("  ERROR: Suspiciously short config from $host — skipping");
        return undef;
    }

    return $config;
}

sub emit {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}

sub usage {
    die "Usage: $0 -h <host>|-f <file> [-u user] [-p pass] [-l logfile] [-t timeout_secs]\n";
}
```