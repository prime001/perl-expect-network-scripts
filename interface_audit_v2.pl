```perl
#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Piece;
use File::Basename;

=head1 CRITICAL SYSLOG MONITOR
Audit network device syslog for critical events, errors, and potential failures.
Identifies stability issues, hardware faults, routing problems, and configuration
errors. Generates compliance-ready audit reports.

USAGE:
  ./critical_syslog_monitor.pl --device 192.168.1.100 --user admin --pass secret
  ./critical_syslog_monitor.pl --file devices.txt --user admin --pass secret --log audit.log

PREREQUISITES:
  - Net::SSH::Expect Perl module installed
  - SSH access to devices (Cisco IOS/NX-OS, Juniper, Arista compatible)
  - Credentials with read/view permissions
  - Device must support 'show log' or 'show messages' commands

EXAMPLES:
  # Check single device, output to STDOUT
  ./critical_syslog_monitor.pl --device 10.0.1.1 --user admin --pass admin123

  # Audit multiple devices, save to log file with custom severity filter
  ./critical_syslog_monitor.pl --file inventory.txt --user netadmin --pass P@ssw0rd \
    --log /var/log/syslog_audit_$(date +%Y%m%d).log --severity "CRITICAL|ERROR|FAIL|DOWN"

  # Quick connectivity check with 15 second timeout
  ./critical_syslog_monitor.pl --device 10.0.1.5 --user admin --pass secret --timeout 15

=cut

my ($device, $device_file, $username, $password, $logfile, $timeout, $severity);
my @devices;

GetOptions(
    'device=s'    => \$device,
    'file=s'      => \$device_file,
    'user=s'      => \$username,
    'pass=s'      => \$password,
    'log=s'       => \$logfile,
    'timeout=i'   => \$timeout,
    'severity=s'  => \$severity,
) or die "Error in command line arguments\n";

$timeout  ||= 30;
$severity ||= 'CRITICAL|ERROR|FAIL|DOWN';

if ($device) {
    push @devices, $device;
} elsif ($device_file) {
    unless (open my $fh, '<', $device_file) {
        die "Cannot open device file $device_file: $!\n";
    }
    while (<$fh>) {
        chomp;
        next if /^#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
} else {
    die "Must specify either --device or --file\n";
}

unless ($username && $password) {
    die "Username and password required (--user and --pass)\n";
}

my $report_fh = \*STDOUT;
if ($logfile) {
    unless (open $report_fh, '>', $logfile) {
        die "Cannot create log file $logfile: $!\n";
    }
}

my $script_name = basename($0);
my $timestamp = Time::Piece->new()->strftime("%Y-%m-%d %H:%M:%S");

print $report_fh "$script_name - Critical Syslog Audit Report\n";
print $report_fh "=" x 85 . "\n";
print $report_fh "Generated: $timestamp\n";
print $report_fh "Devices: " . scalar(@devices) . "\n";
print $report_fh "Severity Filter: $severity\n";
print $report_fh "=" x 85 . "\n\n";

my ($total_devices, $devices_ok, $devices_failed, $total_issues) = (0, 0, 0, 0);

foreach my $dev (@devices) {
    $total_devices++;
    print "Auditing $dev...\n";
    
    my $ssh = Net::SSH::Expect->new(
        host     => $dev,
        user     => $username,
        password => $password,
        timeout  => $timeout,
        raw_pty  => 1,
    );
    
    unless ($ssh->login()) {
        print $report_fh "[FAIL] $dev - SSH authentication failed\n";
        $devices_failed++;
        print STDERR "Authentication failed on $dev\n";
        next;
    }
    
    print $report_fh "\n[Device] $dev\n";
    print $report_fh "-" x 85 . "\n";
    
    my $device_issues = 0;
    
    eval {
        my $log_output = $ssh->exec("show log | include $severity");
        unless ($log_output) {
            $log_output = $ssh->exec("show messages | include $severity");
        }
        
        my @lines = split /\n/, $log_output;
        foreach my $line (@lines) {
            $line =~ s/^\s+|\s+$//g;
            next if !$line || $line =~ /^--More--/ || $line =~ /No entries/i;
            
            if ($line =~ /($severity)/i) {
                print $report_fh "  $line\n";
                $device_issues++;
                $total_issues++;
            }
        }
    };
    
    if ($@) {
        print $report_fh "[ERROR] Exception: $@\n";
        $devices_failed++;
    } else {
        if ($device_issues == 0) {
            print $report_fh "  [OK] No critical events detected\n";
            $devices_ok++;
        } else {
            print $report_fh "  [ALERT] $device_issues critical event(s) found\n";
        }
    }
    
    $ssh->close();
}

print $report_fh "\n" . "=" x 85 . "\n";
print $report_fh "[SUMMARY]\n";
print $report_fh "  Total devices: $total_devices\n";
print $report_fh "  Devices checked successfully: $devices_ok\n";
print $report_fh "  Devices with connection failures: $devices_failed\n";
print $report_fh "  Total critical events found: $total_issues\n";
print $report_fh "  Completed: " . Time::Piece->new()->strftime("%Y-%m-%d %H:%M:%S") . "\n";

close $report_fh if $logfile;

my $exit_code = ($total_issues > 0 || $devices_failed > 0) ? 1 : 0;
exit($exit_code);
```