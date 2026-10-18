```perl
#!/usr/bin/perl

=head1 NAME

device_health_monitor.pl - Monitor device hardware health via SSH

=head1 SYNOPSIS

    device_health_monitor.pl --device <ip> --user <username> --password <password>
    device_health_monitor.pl --file devices.txt --user <username> --password <password>
    device_health_monitor.pl --device 10.0.0.1 --user admin --password secret --log health.log

=head1 DESCRIPTION

Connects to network devices via SSH and monitors hardware health metrics including
CPU utilization, memory usage, temperature sensors, and power supply status. Useful
for proactive device monitoring and capacity planning. Supports Cisco IOS/IOS-XE
platforms and outputs results to STDOUT and optional log file.

Prerequisites: Net::SSH::Expect module, device IP/hostname, valid SSH credentials

=head1 AUTHOR

Network Engineering Portfolio - Real-world device monitoring utility

=cut

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Localtime;
use FileHandle;

my ($device, $file, $user, $password, $logfile);
GetOptions(
    'device=s'   => \$device,
    'file=s'     => \$file,
    'user=s'     => \$user,
    'password=s' => \$password,
    'log=s'      => \$logfile,
) or die "Error in command line arguments\n";

die "Usage: $0 --device <ip> OR --file <file> --user <user> --password <pass>\n"
    unless ($device || $file) && $user && $password;

my @devices = $device ? ($device) : read_device_file($file);

my $log;
if ($logfile) {
    $log = FileHandle->new(">> $logfile") or warn "Cannot open log: $!\n";
    log_message($log, "=== Device Health Monitor Started ===");
}

foreach my $host (@devices) {
    monitor_device($host, $user, $password, $log);
}

log_message($log, "=== Monitor Complete ===\n") if $log;
close($log) if $log;

sub monitor_device {
    my ($host, $user, $pass, $log) = @_;
    
    print "\n[*] Connecting to $host...\n";
    log_message($log, "[*] Connecting to $host...");
    
    my $ssh = Net::SSH::Expect->new(
        host     => $host,
        password => $pass,
        user     => $user,
        timeout  => 30,
        raw_pty  => 1,
    );
    
    my ($login_output, $errorcode);
    eval {
        ($login_output, $errorcode) = $ssh->login();
    };
    
    if ($errorcode || !$login_output) {
        my $err = "ERROR: Failed to authenticate on $host";
        print "$err\n";
        log_message($log, $err);
        return;
    }
    
    print "[+] Connected to $host\n";
    log_message($log, "[+] Successfully connected");
    
    eval {
        # Disable paging
        $ssh->send("terminal length 0");
        $ssh->waitfor('> ', 5) || $ssh->waitfor('# ', 5);
        
        # Check CPU utilization
        $ssh->send("show processes cpu | include CPU utilization");
        my $cpu_output = $ssh->waitfor('# ', 10);
        parse_and_report("CPU Utilization", $cpu_output, $log, $host);
        
        # Check memory usage
        $ssh->send("show processes memory | include Processor Pool");
        my $mem_output = $ssh->waitfor('# ', 10);
        parse_and_report("Memory Usage", $mem_output, $log, $host);
        
        # Check temperature sensors (if supported)
        $ssh->send("show environment all 2>/dev/null | include Temperature|degrees");
        my $temp_output = $ssh->waitfor('# ', 10);
        if ($temp_output && $temp_output !~ /Invalid command/) {
            parse_and_report("Temperature", $temp_output, $log, $host);
        }
        
        # Check power supplies
        $ssh->send("show env power | include Power");
        my $pwr_output = $ssh->waitfor('# ', 10);
        parse_and_report("Power Supplies", $pwr_output, $log, $host);
        
        $ssh->send("exit");
        $ssh->close();
    };
    
    if ($@) {
        print "ERROR: Command execution failed on $host: $@\n";
        log_message($log, "ERROR: Command execution failed: $@");
    }
    
    print "[+] $host health check complete\n";
    log_message($log, "[+] $host health check complete");
}

sub parse_and_report {
    my ($metric, $output, $log, $host) = @_;
    
    return unless defined $output && $output;
    
    my @lines = split /\n/, $output;
    my @relevant = grep { $_ !~ /^(show|#|>)/ && $_ =~ /\S/ } @lines;
    
    if (@relevant) {
        print "  [$metric]:\n";
        log_message($log, "    [$metric]:");
        foreach my $line (@relevant) {
            $line =~ s/^\s+|\s+$//g;
            print "    $line\n" if $line;
            log_message($log, "      $line") if $line;
        }
    }
}

sub read_device_file {
    my ($file) = @_;
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    my @devices = grep { chomp; /\S/ && !/^#/ } <$fh>;
    close $fh;
    die "No valid devices found in $file\n" unless @devices;
    return @devices;
}

sub log_message {
    my ($log, $msg) = @_;
    return unless $log;
    my $ts = scalar localtime;
    print $log "[$ts] $msg\n";
}

1;
```