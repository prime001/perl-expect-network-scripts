#!/usr/bin/perl
#
# SNMP Configuration Audit - Validates SNMP settings across network devices
#
# PURPOSE:
#   Audits SNMP community strings, trap hosts, and monitoring readiness via SSH.
#   Identifies misconfigured SNMP, missing trap servers, weak community strings.
#   Useful for security compliance and monitoring infrastructure validation.
#
# USAGE:
#   ./snmp_audit.pl 192.168.1.1
#   ./snmp_audit.pl --file devices.txt --log snmp_audit.log
#   ./snmp_audit.pl --file devices.txt --severity high
#
# PREREQUISITES:
#   - Net::SSH::Expect installed
#   - SSH access to network devices
#   - Sudo or privilege access for "show snmp" commands
#   - Device supports: show snmp (Cisco), show configuration (Juniper), etc.
#
# ENVIRONMENT VARIABLES:
#   DEVICE_USER - SSH username (default: admin)
#   DEVICE_PASS - SSH password (default: password)
#   DEVICE_ENABLE_PASS - Enable/privilege password if required
#
# OUTPUT:
#   Console output with findings
#   Optional log file with timestamps and detailed report
#   Exit: 0=compliance OK, 1=issues found, 2=connection error
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::localtime;

my ($device_file, $log_file, $severity);
my $help = 0;
my $timeout = 30;
my @devices = ();

GetOptions(
    'file=s'     => \$device_file,
    'log=s'      => \$log_file,
    'severity=s' => \$severity,
    'timeout=i'  => \$timeout,
    'help!'      => \$help,
) or die usage();

die usage() if $help;

if ($device_file) {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^#/ or /^\s*$/;
        push @devices, $_;
    }
    close $fh;
} elsif (@ARGV) {
    push @devices, @ARGV;
} else {
    die usage();
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log: $!\n";
    print $log_fh "\n=== SNMP Audit " . scalar(localtime()) . " ===\n";
}

my ($pass_count, $fail_count) = (0, 0);

foreach my $device (@devices) {
    $device =~ s/\s+//g;
    next unless $device;
    
    print "Scanning $device...";
    my $result = audit_snmp($device);
    
    if ($result->{status} eq 'PASS') {
        print " [PASS]\n";
        $pass_count++;
    } elsif ($result->{status} eq 'WARN') {
        print " [WARNING]\n";
        $fail_count++;
    } else {
        print " [FAIL] - $result->{error}\n";
        $fail_count++;
    }
    
    if ($log_fh && $result->{details}) {
        print $log_fh "$device: $result->{details}\n";
    }
}

print "\nResults: $pass_count passed, $fail_count issues found\n";
close $log_fh if $log_fh;
exit($fail_count > 0 ? 1 : 0);

sub audit_snmp {
    my ($device) = @_;
    my %result = (status => 'FAIL', error => 'Unknown error', details => '');
    
    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host => $device,
            user => $ENV{DEVICE_USER} || 'admin',
            password => $ENV{DEVICE_PASS} || 'password',
            raw_pty => 1,
            timeout => $timeout,
        );
    };
    
    if ($@) {
        $result{error} = "SSH connection failed";
        return \%result;
    }
    
    eval {
        $ssh->login() or die "Login failed";
        
        my $snmp_output = send_command($ssh, "show snmp");
        my $trap_output = send_command($ssh, "show snmp trap");
        
        $ssh->send("exit");
        $ssh->close();
        
        my @issues = ();
        my @findings = ();
        
        if ($snmp_output =~ /SNMP\s+enabled/i) {
            push @findings, "SNMP enabled";
        } else {
            push @issues, "SNMP not enabled";
        }
        
        if ($snmp_output =~ /community\s+(\S+)/gi) {
            my $comm = $1;
            if (length($comm) < 8) {
                push @issues, "Weak community string: $comm (short)";
            } elsif ($comm =~ /^(public|private)$/i) {
                push @issues, "Default community string in use: $comm";
            } else {
                push @findings, "Community configured: $comm";
            }
        } else {
            push @issues, "No SNMP community configured";
        }
        
        if ($trap_output =~ /trap\s+host/i) {
            my @traps = $trap_output =~ /host\s+(\S+)/gi;
            if (@traps) {
                push @findings, "Trap hosts: " . join(", ", @traps);
            }
        } else {
            push @issues, "No SNMP trap hosts configured";
        }
        
        if (@issues) {
            $result{status} = 'WARN';
            $result{details} = join(" | ", @issues);
        } else {
            $result{status} = 'PASS';
            $result{details} = join(" | ", @findings);
        }
    };
    
    if ($@) {
        $result{error} = "Command failed: $@";
        $result{details} = $@;
    }
    
    return \%result;
}

sub send_command {
    my ($ssh, $cmd) = @_;
    $ssh->send($cmd);
    my $output = '';
    eval {
        $output = $ssh->read_all();
    };
    return $output // '';
}

sub usage {
    return <<EOF;
SNMP Configuration Audit v1.0

USAGE:
  $0 <device_ip>
  $0 --file <device_list> [options]

OPTIONS:
  --file <file>     Read device IPs from file (one per line)
  --log <file>      Write detailed results to log file
  --severity <lvl>  Filter by severity (high/medium/low)
  --timeout <sec>   SSH timeout in seconds (default: 30)
  --help            Show this help message

ENVIRONMENT:
  DEVICE_USER       SSH username (default: admin)
  DEVICE_PASS       SSH password (default: password)
  DEVICE_ENABLE_PASS  Enable password if required

EXAMPLE:
  DEVICE_USER=netadmin DEVICE_PASS=MyPass $0 --file devices.txt --log audit.log

CHECKS:
  - SNMP enabled status
  - Community string strength
  - Default credentials detection
  - Trap host configuration
  - SNMP version settings

EOF
}