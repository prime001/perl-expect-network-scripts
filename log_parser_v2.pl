```perl
#!/usr/bin/perl
# Configuration Compliance Checker - Verify network device config policies
# Purpose: SSH into Cisco IOS devices and verify configuration compliance
# Usage: ./config_compliance_checker.pl 192.168.1.1 --user admin --pass secret
#        ./config_compliance_checker.pl --file devices.txt --user admin --pass secret --log results.txt
# Prerequisites: Net::SSH::Expect module, SSH access to devices with username/password auth

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Localtime;

my ($device, $file, $logfile, $username, $password);

GetOptions(
    'device=s'  => \$device,
    'file=s'    => \$file,
    'log=s'     => \$logfile,
    'user=s'    => \$username,
    'pass=s'    => \$password,
) or die "Invalid command line arguments\n";

die "Username and password required\n" unless $username && $password;
die "Specify --device or --file\n" unless $device || $file;

my @devices = $device ? ($device) : read_device_list($file);
my $log;

if ($logfile) {
    open($log, '>>', $logfile) or die "Cannot open logfile: $!\n";
    print $log "\n=== Compliance Check " . scalar(localtime()) . " ===\n";
}

foreach my $host (@devices) {
    verify_device($host, $log);
}

close $log if $log;
print "\nCompliance check completed.\n";
exit 0;

sub verify_device {
    my ($host, $logfh) = @_;
    my $ssh;
    
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $host,
            user     => $username,
            password => $password,
            timeout  => 15,
        );
        $ssh->login() or die "Login failed";
    };
    
    if ($@) {
        output("ERROR: Cannot connect to $host", $logfh);
        return;
    }
    
    output("\n=== Device: $host ===", $logfh);
    
    eval {
        my $version = get_command($ssh, "show version | include Version");
        output("  Version: $version", $logfh) if $version;
        
        my $hostname = get_command($ssh, "show run | include hostname");
        output("  Hostname: $hostname", $logfh) if $hostname;
        
        check_ntp($ssh, $logfh);
        check_snmp($ssh, $logfh);
        check_ssh($ssh, $logfh);
        
        $ssh->close();
    };
    
    if ($@) {
        output("ERROR: Command execution failed on $host: $@", $logfh);
    }
}

sub check_ntp {
    my ($ssh, $logfh) = @_;
    my $status = get_command($ssh, "show ntp status | include Clock");
    
    if ($status && $status =~ /synchronized/) {
        output("  NTP: PASS (synchronized)", $logfh);
    } else {
        output("  NTP: FAIL (not synchronized or unconfigured)", $logfh);
    }
}

sub check_snmp {
    my ($ssh, $logfh) = @_;
    my $config = get_command($ssh, "show run | include snmp-server");
    
    if ($config && length($config) > 1) {
        output("  SNMP: PASS (configured)", $logfh);
    } else {
        output("  SNMP: FAIL (not configured)", $logfh);
    }
}

sub check_ssh {
    my ($ssh, $logfh) = @_;
    my $config = get_command($ssh, "show run | include ip ssh");
    
    if ($config && length($config) > 1) {
        output("  SSH: PASS (configured)", $logfh);
    } else {
        output("  SSH: FAIL (not configured or disabled)", $logfh);
    }
}

sub get_command {
    my ($ssh, $cmd) = @_;
    $ssh->exec($cmd);
    my $output = $ssh->read_all();
    my @lines = split /\n/, $output;
    return $lines[0] if @lines;
    return "";
}

sub output {
    my ($message, $logfh) = @_;
    print "$message\n";
    print $logfh "$message\n" if $logfh;
}

sub read_device_list {
    my ($filename) = @_;
    open my $fh, '<', $filename or die "Cannot open device file: $!\n";
    my @devices = grep { chomp; $_ && !/^#/ } <$fh>;
    close $fh;
    return @devices;
}
```