#!/usr/bin/env perl
use strict;
use warnings;
use Expect;
use Getopt::Long;
use Time::HiRes qw(time);

=head1 NAME
device_health_check.pl - Monitor CPU, memory, temperature on network devices

=head1 SYNOPSIS
    device_health_check.pl --host <ip|hostname> [--user <username>] [--pass <password>] [--logfile <path>]
    device_health_check.pl --file <device_list.txt> [--user <username>] [--pass <password>]

=head1 DESCRIPTION
Connects to network devices via SSH and collects health metrics:
- CPU utilization percentage
- Memory usage percentage  
- System uptime
- Temperature readings (if available)

Supports Cisco IOS, IOS-XE, NX-OS devices. Reports thresholds exceeded to STDOUT and optional logfile.

=head1 PREREQUISITES
    Expect.pm (Net::Expect or standard Expect)
    SSH access to target devices
    Cisco network engineer credentials

=head1 OPTIONS
    --host         Device IP/hostname (required unless --file)
    --file         Text file with one device per line
    --user         SSH username (default: env SSH_USER or 'admin')
    --pass         SSH password (default: prompts if needed)
    --logfile      Optional log file for results
    --timeout      SSH timeout in seconds (default: 30)

=cut

my ($host, $file, $user, $password, $logfile, $timeout);
GetOptions(
    'host=s'    => \$host,
    'file=s'    => \$file,
    'user=s'    => \$user,
    'pass=s'    => \$password,
    'logfile=s' => \$logfile,
    'timeout=i' => \$timeout,
) or die "Error in command line arguments\n";

$timeout //= 30;
$user //= $ENV{SSH_USER} // 'admin';
die "Must specify --host or --file\n" unless ($host || $file);

my @devices = $host ? ($host) : read_devices($file);
die "No valid devices found\n" unless @devices;

my $log;
open($log, '>>', $logfile) if $logfile;

foreach my $dev (@devices) {
    check_health($dev, $user, $password, $log);
}
close($log) if $log;
print "Health check complete\n";

sub check_health {
    my ($device, $user, $pass, $log) = @_;
    my $exp = Expect->new();
    $exp->log_stdout(0);
    $exp->debug(0);
    $exp->timeout($timeout);
    
    print "\n=== $device ===\n";
    write_log($log, "[$device] Health check started at " . scalar localtime);
    
    eval {
        $exp->spawn("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $user\@$device")
            or die "Cannot spawn SSH: $!\n";
        
        $exp->expect(
            [ 'password:', sub { $exp->send("$pass\n") if $pass } ],
            [ 'Password:', sub { $exp->send("$pass\n") if $pass } ],
        );
        
        my $prompt = qr/[\w\-]+[#>]/;
        $exp->expect($timeout, $prompt) or die "No device prompt\n";
        
        $exp->send("terminal length 0\n");
        $exp->expect($timeout, $prompt);
        
        # CPU check
        $exp->send("show processes cpu | include CPU utilization\n");
        $exp->expect($timeout, $prompt);
        if ($exp->before =~ /(\d+)%\s*Busy/) {
            my $cpu = $1;
            my $alert = $cpu > 80 ? " [WARN]" : "";
            print "CPU Usage: $cpu%$alert\n";
            write_log($log, "[$device] CPU: $cpu%");
        }
        
        # Memory check
        $exp->send("show memory statistics\n");
        $exp->expect($timeout, $prompt);
        if ($exp->before =~ /(\d+)\s+bytes\s+total.*?(\d+)\s+bytes\s+free/s) {
            my ($total, $free) = ($1, $2);
            my $used_pct = int((($total - $free) / $total) * 100);
            my $alert = $used_pct > 85 ? " [WARN]" : "";
            print "Memory Usage: $used_pct%$alert\n";
            write_log($log, "[$device] Memory: $used_pct%");
        }
        
        # Uptime check
        $exp->send("show version | include uptime\n");
        $exp->expect($timeout, $prompt);
        if ($exp->before =~ /uptime is\s+(.+?)[\r\n]/) {
            my $uptime = $1;
            print "Uptime: $uptime\n";
            write_log($log, "[$device] Uptime: $uptime");
        }
        
        # Temperature (optional)
        $exp->send("show environment | include Temperature\n");
        $exp->expect($timeout, $prompt);
        my @temps = $exp->before =~ /(\d+)\s*[°C|C]/gi;
        if (@temps) {
            my $max_t = (sort { $b <=> $a } @temps)[0];
            my $alert = $max_t > 70 ? " [WARN]" : "";
            print "Max Temperature: ${max_t}C$alert\n";
            write_log($log, "[$device] Temp: ${max_t}C");
        }
        
        $exp->send("exit\n");
        $exp->soft_close();
        write_log($log, "[$device] Completed successfully");
    };
    
    if ($@) {
        print "[ERROR] $@\n";
        write_log($log, "[$device] ERROR: $@");
        $exp->hard_close() if $exp;
    }
}

sub read_devices {
    my ($filepath) = @_;
    return () unless -f $filepath;
    open(my $fh, '<', $filepath) or die "Cannot open $filepath: $!\n";
    my @devices;
    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^#/ || $line =~ /^\s*$/;
        push @devices, $line;
    }
    close($fh);
    return @devices;
}

sub write_log {
    my ($log, $msg) = @_;
    return unless $log;
    print $log "$msg\n";
    $log->flush;
}