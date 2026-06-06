```perl
#!/usr/bin/perl
# bgp_flap_monitor.pl - BGP peer flap detection and zero-prefix alerting
#
# PURPOSE:
#   Connects to Cisco IOS/IOS-XE routers via SSH and analyzes BGP summary
#   output to detect recently-flapped peers (uptime under threshold) and
#   established peers advertising zero prefixes. Useful for post-change
#   validation and automated NOC health sweeps.
#
# USAGE:
#   Single device:  perl bgp_flap_monitor.pl -h 192.168.1.1 -u admin -p pass
#   Device file:    perl bgp_flap_monitor.pl -f devices.txt -u admin -p pass
#   With log:       perl bgp_flap_monitor.pl -h 192.168.1.1 -u admin -p pass -l bgp.log
#   Custom threshold (seconds):
#                   perl bgp_flap_monitor.pl -h 192.168.1.1 -u admin -p pass -t 600
#
# PREREQUISITES:
#   cpan install Expect Getopt::Long
#   SSH key auth preferred; password auth supported via -p flag
#   Tested: Cisco IOS 15.x, IOS-XE 16.x/17.x
#
# DEVICE FILE FORMAT:
#   One IP or hostname per line; lines starting with # are skipped

use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $logfile, $threshold, $help);
$threshold = 300;

GetOptions(
    'h|host=s'      => \$host,
    'f|file=s'      => \$file,
    'u|user=s'      => \$user,
    'p|pass=s'      => \$pass,
    'l|log=s'       => \$logfile,
    't|threshold=i' => \$threshold,
    'help'          => \$help,
) or die usage();

die usage() if $help or (!$host and !$file) or !$user;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $file) or die "Cannot open device file $file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ or /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log file $logfile: $!\n";
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
log_out("=== BGP Flap Monitor: $ts | threshold=${threshold}s ===");

for my $dev (@devices) {
    log_out("\n[+] Connecting to $dev ...");
    check_device($dev);
}

close $log_fh if $log_fh;

sub check_device {
    my ($dev) = @_;

    my $exp = Expect->new;
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    my @ssh_cmd = ('ssh',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'ConnectTimeout=10',
        '-l', $user, $dev);

    unless ($exp->spawn(@ssh_cmd)) {
        log_out("  ERROR: spawn failed for $dev: $!");
        return;
    }

    my $authed = 0;
    $exp->expect(15,
        [ qr/[Pp]assword:/,   sub { $exp->send("$pass\n"); exp_continue; } ],
        [ qr/yes\/no/,        sub { $exp->send("yes\n");   exp_continue; } ],
        [ qr/[>#]\s*$/,       sub { $authed = 1; } ],
        [ timeout =>          sub { log_out("  ERROR: connection timeout to $dev"); } ],
    );

    unless ($authed) {
        log_out("  ERROR: authentication failed for $dev");
        $exp->soft_close;
        return;
    }

    $exp->send("terminal length 0\n");
    $exp->expect(5, qr/[>#]\s*$/);

    my $label = $dev;
    $exp->send("show version | include hostname\n");
    $exp->expect(5, qr/[>#]\s*$/);
    $label = $1 if $exp->before() =~ /hostname\s+(\S+)/i;

    $exp->send("show ip bgp summary\n");
    $exp->expect(15, qr/[>#]\s*$/);
    my $raw = $exp->before();

    $exp->send("exit\n");
    $exp->soft_close;

    parse_summary($label, $dev, $raw);
}

sub parse_summary {
    my ($label, $ip, $raw) = @_;

    my (@flapped, @zero_pfx, $total);

    for my $line (split /\n/, $raw) {
        # IOS BGP summary peer line format:
        # Neighbor  V  AS  MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
        next unless $line =~ /^(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)/;
        my ($peer, $as, $updown, $state) = ($1, $2, $3, $4);
        $total++;

        if ($state =~ /^\d+$/) {
            push @zero_pfx, "$peer (AS$as)" if $state == 0;
            my $secs = uptime_to_secs($updown);
            if (defined $secs && $secs < $threshold) {
                push @flapped, sprintf("    %-18s AS%-8s up/down=%-12s prefixes=%s", $peer, $as, $updown, $state);
            }
        } else {
            push @flapped, sprintf("    %-18s AS%-8s up/down=%-12s state=%s", $peer, $as, $updown, $state);
        }
    }

    $total //= 0;
    log_out(sprintf("  Router: %s (%s) | peers found: %d", $label, $ip, $total));

    if (@flapped) {
        log_out("  [WARN] Recently flapped or non-Established peers:");
        log_out($_) for @flapped;
    } else {
        log_out("  [OK]   No recently flapped peers");
    }

    if (@zero_pfx) {
        log_out("  [WARN] Established peers with 0 prefixes received: " . join(', ', @zero_pfx));
    }
}

sub uptime_to_secs {
    my ($t) = @_;
    return undef if $t eq 'never';
    return $1*3600 + $2*60 + $3 if $t =~ /^(\d+):(\d+):(\d+)$/;
    return $1*604800 + $2*86400  if $t =~ /^(\d+)w(\d+)d$/;
    return $1*86400  + $2*3600   if $t =~ /^(\d+)d(\d+)h$/;
    return undef;
}

sub log_out {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}

sub usage {
    return <<'END';
Usage: bgp_flap_monitor.pl -h <host>|-f <file> -u <user> [-p <pass>] [-l <log>] [-t <secs>]
  -h  Device IP or hostname
  -f  File with device list (one per line, # comments ok)
  -u  SSH username
  -p  SSH password (omit for key-based auth)
  -l  Log file (appended)
  -t  Flap threshold in seconds (default: 300)
END
}
```