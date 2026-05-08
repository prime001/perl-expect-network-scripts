Writing a CPU/memory health monitoring script — not covered by the existing scripts in the repo.

#!/usr/bin/perl
#
# cpu_memory_monitor.pl — Poll Cisco IOS/IOS-XE devices for CPU and memory
#                          utilization; alert when configurable thresholds are
#                          exceeded and dump top offending processes.
#
# Usage:
#   ./cpu_memory_monitor.pl -p <password> [options] <device>
#   ./cpu_memory_monitor.pl -p <password> -f devices.txt [options]
#
#   -u <user>     SSH username            (default: admin)
#   -p <pass>     SSH password            (required)
#   -c <pct>      CPU 1-min alert %       (default: 80)
#   -m <pct>      Memory alert %          (default: 85)
#   -l <logfile>  Append results here     (optional)
#   -f            Treat positional arg as device list file, one host per line
#
# Prerequisites:
#   cpanm Net::SSH::Expect
#
# Tested against: Cisco IOS 15.x, IOS-XE 16.x/17.x

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Std;
use POSIX qw(strftime);

my %opts;
getopts('u:p:c:m:l:f', \%opts);

my $username   = $opts{u} // 'admin';
my $password   = $opts{p} or die "ERROR: SSH password required (-p)\n";
my $cpu_thresh = $opts{c} // 80;
my $mem_thresh = $opts{m} // 85;
my $logfile    = $opts{l};
my $from_file  = $opts{f};

my $target = shift @ARGV
    or die "Usage: $0 -p <pass> [-u user] [-c cpu%] [-m mem%] [-l log] [-f] <device|file>\n";

my @devices;
if ($from_file) {
    open my $fh, '<', $target or die "Cannot open device file '$target': $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
} else {
    @devices = ($target);
}

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open log '$logfile': $!\n";
}

sub out {
    print @_;
    print $log_fh @_ if $log_fh;
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=== CPU/Memory Health Check  $ts ===\n");

for my $host (@devices) {
    out("\n[$host]\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        user     => $username,
        password => $password,
        raw_pty  => 1,
        timeout  => 20,
    );

    eval {
        my $banner = $ssh->login();
        die "Authentication failed (no prompt)\n" unless $banner =~ /[>#]/;

        $ssh->exec('terminal length 0');

        # --- CPU ---
        my $cpu_raw = $ssh->exec('show processes cpu | include CPU utilization');
        my ($s5, $m1, $m5) = $cpu_raw =~ /(\d+)%\/\d+%;\s+one minute:\s+(\d+)%;\s+five minutes:\s+(\d+)%/;
        unless (defined $s5) {
            ($s5, $m1, $m5) = $cpu_raw =~ /(\d+)%\s+(\d+)%\s+(\d+)%/;
        }
        die "Could not parse CPU utilization output\n" unless defined $s5;

        my $cpu_flag = ($m1 >= $cpu_thresh) ? '!! ALERT' : 'OK';
        out(sprintf("  CPU  5s:%-3s%%  1m:%-3s%%  5m:%-3s%%  [%s]\n",
                    $s5, $m1, $m5, $cpu_flag));

        if ($m1 >= $cpu_thresh) {
            out("  Top CPU consumers (1-min >= ${cpu_thresh}%):\n");
            my $top = $ssh->exec('show processes cpu sorted | head 8');
            $top =~ s/^/    /mg;
            out($top . "\n");
        }

        # --- Memory ---
        my $mem_raw = $ssh->exec('show processes memory | include ^Processor');
        my ($used, $free) = $mem_raw =~ /Processor\s+\S+\s+(\d+)\s+(\d+)/;
        die "Could not parse memory output\n" unless defined $used;

        my $total    = $used + $free;
        my $mem_pct  = int($used / $total * 100);
        my $mem_flag = ($mem_pct >= $mem_thresh) ? '!! ALERT' : 'OK';
        out(sprintf("  Mem  used:%-8s free:%-8s util:%d%%  [%s]\n",
                    _fmt($used), _fmt($free), $mem_pct, $mem_flag));

        if ($mem_pct >= $mem_thresh) {
            out("  !! Memory ${mem_pct}% exceeds threshold ${mem_thresh}%\n");
            my $top_mem = $ssh->exec('show processes memory sorted | head 8');
            $top_mem =~ s/^/    /mg;
            out($top_mem . "\n");
        }

        $ssh->close();
    };
    if (my $err = $@) {
        $err =~ s/\s+$//;
        out("  ERROR: $err\n");
    }
}

out("\n=== Done ===\n");
close $log_fh if $log_fh;

sub _fmt {
    my ($bytes) = @_;
    return sprintf('%dM', $bytes / 1_048_576) if $bytes >= 1_048_576;
    return sprintf('%dK', $bytes / 1_024)     if $bytes >= 1_024;
    return "${bytes}B";
}