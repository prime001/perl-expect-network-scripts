Here is the complete script — you'll need to save it yourself as the working directory requires permission. The file should be named `106_ospf_timer_audit.pl`:

```perl
#!/usr/bin/perl
# =============================================================================
# ospf_timer_audit.pl — OSPF Interface Timer & Authentication Consistency Check
#
# PURPOSE:
#   Audits OSPF hello/dead timers and authentication configuration on all OSPF-
#   enabled interfaces across one or more Cisco IOS/IOS-XE devices. Timer
#   mismatches between adjacent routers are a leading cause of OSPF neighbor
#   flaps; this script surfaces them before they cause outages.
#
# USAGE:
#   Single device:   perl ospf_timer_audit.pl -h 192.168.1.1 -u admin -p secret
#   Device list:     perl ospf_timer_audit.pl -f devices.txt -u admin -p secret
#   With log file:   perl ospf_timer_audit.pl -h 192.168.1.1 -u admin -p secret -l audit.log
#   Custom timeout:  perl ospf_timer_audit.pl -h 192.168.1.1 -u admin -p secret -t 45
#
# PREREQUISITES:
#   cpan install Expect
#   Expects Cisco IOS/IOS-XE prompt ending in # (privilege EXEC mode)
#   SSH must be enabled on target devices
#
# OUTPUT:
#   Per-interface: hello timer, dead timer, auth type, OSPF area, network type
#   Flags interfaces with non-default timers (hello != 10s or dead != 40s)
#   Flags interfaces with no authentication configured
# =============================================================================

use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $log_file);
my $timeout = 30;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'l|log=s'      => \$log_file,
    't|timeout=i'  => \$timeout,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOG] [-t TIMEOUT]\n";

die "Provide -h HOST or -f FILE\n"    unless $host || $device_file;
die "Username required (-u)\n"        unless $username;
die "Password required (-p)\n"        unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        s/#.*//;
        s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>', $log_file) or die "Cannot open log $log_file: $!\n";
}

sub log_output {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
log_output("=" x 70 . "\n");
log_output("OSPF Timer & Authentication Audit — $ts\n");
log_output("=" x 70 . "\n\n");

for my $device (@devices) {
    log_output("--- Device: $device ---\n");

    my $exp = Expect->new();
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=$timeout $username\@$device")) {
        log_output("  [ERROR] Failed to spawn SSH to $device\n\n");
        next;
    }

    my $logged_in = 0;
    $exp->expect($timeout,
        [ qr/[Pp]assword:/ => sub {
            $exp->send("$password\n");
            exp_continue;
        }],
        [ qr/#\s*$/ => sub { $logged_in = 1; }],
        [ qr/[Pp]ermission denied/ => sub {
            log_output("  [ERROR] Authentication failed\n\n");
        }],
        [ timeout => sub {
            log_output("  [ERROR] Connection timed out\n\n");
        }],
    );

    unless ($logged_in) {
        $exp->hard_close();
        next;
    }

    $exp->send("terminal length 0\n");
    $exp->expect($timeout, qr/#\s*$/);

    $exp->send("show ip ospf interface\n");
    my $output = '';
    $exp->expect($timeout,
        [ qr/#\s*$/ => sub { $output = $exp->before(); }],
        [ timeout   => sub { log_output("  [ERROR] Command timed out\n"); }],
    );

    $exp->send("exit\n");
    $exp->soft_close();

    if (!$output) {
        log_output("  [WARN] No output received — OSPF may not be configured\n\n");
        next;
    }

    my @interfaces;
    my $current;

    for my $line (split /\n/, $output) {
        if ($line =~ /^(\S+)\s+is\s+(?:up|down),\s+line\s+protocol\s+is\s+(?:up|down)/i) {
            push @interfaces, $current if $current;
            $current = { name => $1, hello => '?', dead => '?', auth => 'none', area => '?', net_type => '?' };
        }
        next unless $current;

        if ($line =~ /Internet Address\s+[\d.]+\/\d+,\s+Area\s+([\d.]+)/) {
            $current->{area} = $1;
        }
        if ($line =~ /Network Type\s+(\S+)/) {
            $current->{net_type} = $1;
        }
        if ($line =~ /Timer intervals configured.*Hello\s+(\d+),\s+Dead\s+(\d+)/) {
            $current->{hello} = $1;
            $current->{dead}  = $2;
        }
        if ($line =~ /Simple password authentication enabled/i) {
            $current->{auth} = 'simple';
        } elsif ($line =~ /Message digest authentication enabled/i) {
            $current->{auth} = 'md5';
        } elsif ($line =~ /No authentication/i) {
            $current->{auth} = 'none';
        }
    }
    push @interfaces, $current if $current;

    if (!@interfaces) {
        log_output("  No OSPF interfaces found on this device\n\n");
        next;
    }

    my $issues = 0;
    for my $iface (@interfaces) {
        my @flags;
        push @flags, "NON-DEFAULT hello=$iface->{hello}s"  if $iface->{hello} ne '?' && $iface->{hello} != 10;
        push @flags, "NON-DEFAULT dead=$iface->{dead}s"    if $iface->{dead}  ne '?' && $iface->{dead}  != 40;
        push @flags, "NO-AUTH"                              if $iface->{auth} eq 'none';

        $issues++ if @flags;

        log_output(sprintf("  %-28s  Area:%-8s  Hello:%-4s  Dead:%-4s  Auth:%-6s  Type:%s%s\n",
            $iface->{name}, $iface->{area},
            $iface->{hello}, $iface->{dead},
            $iface->{auth}, $iface->{net_type},
            @flags ? "\n         [!] " . join(", ", @flags) : ""));
    }

    log_output("\n  Summary: " . scalar(@interfaces) . " OSPF interface(s), $issues issue(s) flagged\n\n");
}

log_output("Audit complete.\n");
close $log_fh if $log_fh;
```

The script audits `show ip ospf interface` output per device, parses hello/dead timers and auth type per interface, and flags anything non-default or missing auth — a distinct operational use case from the existing neighbor-state scripts. It handles connection failures, auth errors, and timeouts cleanly, supports both single-host and device-list modes, and optionally tees output to a log file.