#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::HiRes qw(time);
use File::Spec;

=head1 DEVICE HEALTH MONITOR

Purpose:
  Monitor critical device health metrics: CPU, memory, uptime, interface status
  Useful for rapid health assessment across network infrastructure

Usage:
  ./device_health_monitor.pl --device 192.168.1.1 --user admin --pass password
  ./device_health_monitor.pl --file devices.txt --user admin --pass password --log health.log

Prerequisites:
  - Net::SSH::Expect module (cpan Net::SSH::Expect)
  - SSH access to network devices
  - Device support for: show system, show interfaces, show processes (vendor-specific)
  - Devices running IOS/IOS-XE/NXOS

Options:
  --device <ip>     Target device IP or hostname
  --file <path>     File with device list (one per line)
  --user <user>     SSH username
  --pass <pass>     SSH password (or use expect)
  --port <port>     SSH port (default: 22)
  --timeout <sec>   Connection timeout in seconds (default: 10)
  --log <path>      Log file for results
  --verbose         Show command output details

=cut

my ($device, $device_file, $username, $password, $port, $timeout, $log_file, $verbose);

GetOptions(
    'device=s'   => \$device,
    'file=s'     => \$device_file,
    'user=s'     => \$username,
    'pass=s'     => \$password,
    'port=i'     => \$port,
    'timeout=i'  => \$timeout,
    'log=s'      => \$log_file,
    'verbose!'   => \$verbose,
) or die "Error in command line arguments\n";

$port //= 22;
$timeout //= 10;
die "Usage: $0 --device <ip> | --file <path> --user <user> --pass <password>\n"
    unless ($device || $device_file) && $username;

open my $log_fh, '>>', $log_file or warn "Cannot open log: $log_file\n"
    if $log_file;

sub log_output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}

sub check_device {
    my ($host, $user, $pass, $port, $timeout) = @_;
    my $timestamp = scalar localtime();
    
    log_output("\n[${timestamp}] Checking device: $host");
    
    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $host,
            user     => $user,
            password => $pass,
            port     => $port,
            timeout  => $timeout,
            raw_pty  => 1,
        );
        $ssh->login();
    };
    
    if ($@) {
        log_output("  ERROR: Connection failed - $@");
        return 0;
    }
    
    my %health = (uptime => 'unknown', cpu => 'N/A', memory => 'N/A', interfaces => 0);
    
    my @commands = (
        { cmd => 'show version', pattern => '(uptime|Uptime)' },
        { cmd => 'show processes cpu', pattern => '(CPU|usage)' },
        { cmd => 'show memory', pattern => '(Memory|bytes)' },
        { cmd => 'show interfaces brief', pattern => 'Interface' },
    );
    
    foreach my $cmd_obj (@commands) {
        eval {
            my $output = $ssh->exec($cmd_obj->{cmd});
            if ($verbose) {
                log_output("  CMD: $cmd_obj->{cmd}");
                log_output("    " . join("\n    ", split /\n/, substr($output, 0, 200)));
            }
            
            if ($cmd_obj->{cmd} =~ /uptime|version/) {
                if ($output =~ /uptime[:\s]+(.+?)$/mi || $output =~ /Uptime[:\s]+(.+?)$/mi) {
                    $health{uptime} = $1;
                    log_output("  Uptime: $health{uptime}");
                }
            }
            
            if ($cmd_obj->{cmd} =~ /processes cpu/) {
                if ($output =~ /(\d+(?:\.\d+)?)\s*%/) {
                    $health{cpu} = $1 . '%';
                    log_output("  CPU Usage: $health{cpu}");
                }
            }
            
            if ($cmd_obj->{cmd} =~ /memory/) {
                if ($output =~ /(\d+).*free/i) {
                    $health{memory} = "OK";
                    log_output("  Memory: Available");
                }
            }
            
            if ($cmd_obj->{cmd} =~ /interfaces brief/) {
                my @interfaces = $output =~ /^\s*(\S+)\s+/gm;
                $health{interfaces} = scalar @interfaces;
                my $up_count = $output =~ /up\s+up/g;
                log_output("  Interfaces: $up_count up out of $health{interfaces} total");
            }
        };
        
        if ($@) {
            log_output("  WARNING: Command '$cmd_obj->{cmd}' failed: $@");
        }
    }
    
    eval { $ssh->close(); };
    
    return 1;
}

my @devices;
if ($device) {
    push @devices, $device;
} elsif ($device_file) {
    open my $fh, '<', $device_file or die "Cannot read $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

die "No devices to check\n" unless @devices;

log_output("Device Health Monitor - Started at " . scalar localtime());
log_output("Checking " . scalar(@devices) . " device(s)");

my $start = time();
my $success_count = 0;

foreach my $host (@devices) {
    $success_count++ if check_device($host, $username, $password, $port, $timeout);
}

my $elapsed = time() - $start;
log_output("\nSummary: $success_count/" . scalar(@devices) . " devices reachable (${elapsed}s)");

close $log_fh if $log_fh;
exit($success_count == @devices ? 0 : 1);