```perl
#!/usr/bin/perl
#
# Device Syslog Monitor - Real-time critical syslog event capture and alerting
#
# Purpose:
#   Connects to network devices via SSH and captures critical syslog events in real-time.
#   Monitors for link state changes, errors, warnings, and other critical events.
#   Useful for troubleshooting active issues and detecting problems as they occur.
#
# Usage:
#   ./device_syslog_monitor.pl <device_ip> [<device_ip2> ...] [--log alerts.log] [--timeout 120]
#   ./device_syslog_monitor.pl --file devices.txt --log /tmp/syslog_alerts.txt
#
# Prerequisites:
#   - Perl modules: Expect
#   - SSH access with valid credentials (SSH_USER and SSH_PASS env vars, or key-based auth)
#   - Device supports terminal monitor and syslog output to SSH sessions
#
# Environment Variables:
#   SSH_USER - SSH username (default: admin)
#   SSH_PASS - SSH password (leave unset for key-based auth)

use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);
use File::Basename;

my ($device_file, $logfile, $timeout, $help);
GetOptions(
    'file=s'    => \$device_file,
    'log=s'     => \$logfile,
    'timeout=i' => \$timeout,
    'help'      => \$help,
) or die "Error in command line arguments\n";

$timeout ||= 120;

if ($help) {
    print "Usage: " . basename($0) . " [--file devices.txt] [--log logfile] [--timeout N] [device1] [device2]\n";
    exit 0;
}

my @devices;
if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}
push @devices, @ARGV if @ARGV;

die "No devices specified\n" unless @devices;

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open $logfile: $!\n";
    $log_fh->autoflush(1);
}

log_msg("Syslog monitor started for " . scalar(@devices) . " device(s)", $log_fh);

foreach my $device (@devices) {
    monitor_device($device, $log_fh, $timeout);
}

close $log_fh if $log_fh;

sub monitor_device {
    my ($device, $log_fh, $timeout) = @_;
    my $user = $ENV{SSH_USER} || 'admin';
    my $pass = $ENV{SSH_PASS};
    
    log_msg("Connecting to $device...", $log_fh);
    
    my $exp = Expect->new();
    $exp->timeout($timeout);
    
    eval {
        $exp->spawn("ssh -o ConnectTimeout=10 -l $user $device")
            or die "Cannot spawn SSH to $device: $!";
    };
    
    if ($@) {
        log_msg("ERROR: $device - $@", $log_fh);
        return;
    }
    
    if ($pass) {
        my $matched = $exp->expect(10, 'assword:');
        if (!$matched) {
            log_msg("ERROR: $device - Password prompt timeout", $log_fh);
            $exp->hard_close();
            return;
        }
        $exp->send("$pass\n");
    }
    
    my $connected = 0;
    eval {
        $exp->expect(10, qr/[#>]\s*$/);
        $connected = 1;
    };
    
    unless ($connected) {
        log_msg("ERROR: $device - SSH authentication failed", $log_fh);
        $exp->hard_close();
        return;
    }
    
    $exp->send("terminal monitor\n");
    $exp->expect(2, qr/[#>]\s*$/);
    
    log_msg("CONNECTED: $device - capturing syslog events", $log_fh);
    
    my $start_time = time();
    my $monitor_duration = 3600;
    my %seen_alerts;
    
    while (time() - $start_time < $monitor_duration) {
        my ($pos, $match, $before, $after);
        
        eval {
            ($pos, $match, $before, $after) = $exp->expect(15, '-re', qr/.*[A-Za-z0-9]{2,}.*\n/);
        };
        
        last if !defined $pos || $@;
        next unless $match;
        
        if ($match =~ /^%?([A-Z]+)[_-](\d+)[_-]([A-Z]+)/ || $match =~ /%(.+?)$/) {
            my $alert_sig = substr($match, 0, 80);
            
            if ($match =~ /LINK-[0-9]-UPDOWN|LINEPROTO-[0-9]-UPDOWN/i) {
                my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime());
                my $msg = "[$ts] $device LINK-STATUS: $match";
                print "$msg\n";
                print $log_fh "$msg\n" if $log_fh;
                next;
            }
            
            if ($match =~ /%(.{10,})/i) {
                unless ($seen_alerts{$alert_sig}++) {
                    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime());
                    my $msg = "[$ts] $device: $match";
                    
                    if ($match =~ /ERROR|CRIT|FAIL|DOWN|INVALID/i) {
                        print "*** ALERT: $msg\n";
                        print $log_fh "*** ALERT: $msg\n" if $log_fh;
                    } elsif ($match =~ /WARN|WARN/i) {
                        print "** WARNING: $msg\n";
                        print $log_fh "** WARNING: $msg\n" if $log_fh;
                    }
                }
            }
        }
    }
    
    $exp->send("exit\n");
    $exp->soft_close();
    log_msg("DISCONNECTED: $device - monitoring complete", $log_fh);
}

sub log_msg {
    my ($msg, $log_fh) = @_;
    my $ts = strftime('[%Y-%m-%d %H:%M:%S]', localtime());
    print STDOUT "$ts $msg\n";
    if ($log_fh) {
        print $log_fh "$ts $msg\n";
    }
}
```