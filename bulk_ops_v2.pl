```perl
#!/usr/bin/perl
#
# device_health_check.pl
#
# Purpose:
#   Remote device health monitoring via SSH. Collects CPU, memory,
#   uptime, and interface error metrics for health assessment.
#   Useful for ongoing device health baselines and alerting.
#
# Usage:
#   perl device_health_check.pl <device_ip> [<logfile>]
#   perl device_health_check.pl 192.168.1.1 /tmp/health.log
#
# Prerequisites:
#   - Net::SSH::Expect Perl module
#   - SSH credentials in ENV: NET_USER, NET_PASS
#   - Cisco IOS/IOS-XE device with SSH enabled
#   - Commands: show version, show processes cpu, show memory, show interfaces
#
# Error Handling:
#   - SSH connection timeout: 10 seconds
#   - Command timeout: 5 seconds
#   - Authentication failures logged with details
#   - Unreachable devices reported with timestamp
#

use strict;
use warnings;
use Net::SSH::Expect;
use DateTime;

my $device   = $ARGV[0] || die "Usage: $0 <device_ip> [<logfile>]\n";
my $logfile  = $ARGV[1];
my $username = $ENV{NET_USER} || 'admin';
my $password = $ENV{NET_PASS} || '';
my $timeout  = 10;

sub log_msg {
    my ($msg) = @_;
    my $dt = DateTime->now(time_zone => 'UTC')->iso8601;
    print "[$dt] $msg\n";
    if ($logfile) {
        open my $fh, '>>', $logfile or warn "Cannot write to $logfile: $!\n";
        print $fh "[$dt] $msg\n";
        close $fh;
    }
}

sub connect_ssh {
    my ($host, $user, $pass) = @_;
    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => $timeout,
    );
    
    eval { $ssh->login(); };
    if ($@) {
        log_msg("ERROR: SSH connection to $host failed - $@");
        return undef;
    }
    return $ssh;
}

sub disable_paging {
    my ($ssh) = @_;
    $ssh->send("terminal length 0");
    $ssh->waitfor('.*#', 2);
}

sub get_hostname {
    my ($ssh) = @_;
    $ssh->send("show version | include -i ^hostname");
    my $output = $ssh->waitfor('.*#', 3);
    return $1 if $output =~ /hostname\s+(\S+)/i;
    return 'UNKNOWN';
}

sub get_uptime {
    my ($ssh) = @_;
    $ssh->send("show version | include uptime");
    my $output = $ssh->waitfor('.*#', 3);
    return $1 if $output =~ /uptime is\s+(.+?)[\r\n]/;
    return 'N/A';
}

sub get_cpu {
    my ($ssh) = @_;
    $ssh->send("show processes cpu | include CPU utilization");
    my $output = $ssh->waitfor('.*#', 3);
    if ($output =~ /(\d+)%/) {
        return $1;
    }
    return undef;
}

sub get_memory {
    my ($ssh) = @_;
    $ssh->send("show memory | include Processor");
    my $output = $ssh->waitfor('.*#', 3);
    if ($output =~ /(\d+)K\s+total.*?(\d+)K\s+free/s) {
        my $used = $1 - $2;
        my $percent = int(($used / $1) * 100);
        return { used => $used, total => $1, free => $2, percent => $percent };
    }
    return { used => 0, total => 0, free => 0, percent => 0 };
}

sub count_interface_errors {
    my ($ssh) = @_;
    $ssh->send("show interfaces | include -E 'input errors|CRC'");
    my $output = $ssh->waitfor('.*#', 5);
    my $count = 0;
    foreach my $line (split /\n/, $output) {
        $count++ if $line =~ /\d+\s+input errors/i || $line =~ /\d+\s+CRC/i;
    }
    return $count;
}

sub assess_health {
    my (%data) = @_;
    my $status = 'HEALTHY';
    
    if ($data{cpu} && $data{cpu} > 80) {
        $status = 'WARNING: High CPU (' . $data{cpu} . '%)';
    }
    if ($data{memory}->{percent} && $data{memory}->{percent} > 85) {
        $status = 'WARNING: High Memory (' . $data{memory}->{percent} . '%)';
    }
    if ($data{errors} && $data{errors} > 0) {
        $status = 'WARNING: ' . $data{errors} . ' interface(s) with errors';
    }
    
    return $status;
}

# Main execution
log_msg("Starting health check for $device");

my $ssh = connect_ssh($device, $username, $password);
unless ($ssh) {
    log_msg("CRITICAL: Cannot connect to $device");
    exit 1;
}

eval {
    disable_paging($ssh);
    
    my %health = (
        hostname => get_hostname($ssh),
        uptime   => get_uptime($ssh),
        cpu      => get_cpu($ssh),
        memory   => get_memory($ssh),
        errors   => count_interface_errors($ssh),
    );
    
    my $status = assess_health(%health);
    
    log_msg("--- Device: $device ($health{hostname}) ---");
    log_msg("Uptime: $health{uptime}");
    log_msg("CPU: " . ($health{cpu} // 'N/A') . "%");
    log_msg("Memory: $health{memory}->{percent}% ($health{memory}->{used}K/$health{memory}->{total}K)");
    log_msg("Interface Errors: $health{errors}");
    log_msg("Status: $status");
    log_msg("-----");
};

if ($@) {
    log_msg("ERROR: Command execution failed - $@");
}

eval { $ssh->close(); };
log_msg("Connection closed");

exit 0;
```