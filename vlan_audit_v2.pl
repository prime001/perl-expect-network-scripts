```perl
#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::localtime;

# ==============================================================================
# route_audit.pl - Network Device Routing Table Audit
# ==============================================================================
# PURPOSE:
#   Validates critical routes exist in device routing tables. Useful for
#   post-deployment verification and monitoring route convergence.
#
# USAGE:
#   ./route_audit.pl --host 192.168.1.1 --user admin [--pass PASSWORD]
#   ./route_audit.pl --file devices.txt --user admin --log results.log
#
# PREREQUISITES:
#   - Net::SSH::Expect Perl module installed
#   - SSH access to network devices (Cisco IOS/XE compatible)
#   - Valid device credentials
#   - Critical routes defined in %CRITICAL_ROUTES hash
#
# OUTPUT:
#   - Console: real-time audit status
#   - Log file: detailed per-device results with timestamps
#
# ==============================================================================

my ($host, $file, $user, $pass, $logfile, $timeout, $help);

GetOptions(
    'host=s'     => \$host,
    'file=s'     => \$file,
    'user=s'     => \$user,
    'pass=s'     => \$pass,
    'log=s'      => \$logfile,
    'timeout=i'  => \$timeout,
    'help'       => \$help,
) or die "Error in command line arguments\n";

die usage() if $help || (!$host && !$file) || !$user;

$timeout   ||= 30;
$logfile   ||= 'route_audit.log';

# Define critical routes to validate (CIDR notation)
my %CRITICAL_ROUTES = (
    '10.0.0.0/8'        => 'Corporate headquarters',
    '172.16.0.0/12'     => 'Branch office networks',
    '192.168.0.0/16'    => 'Management networks',
);

my @devices = $host ? ($host) : read_device_list($file);

open my $logfh, '>>', $logfile or die "Cannot open $logfile: $!\n";

foreach my $device (@devices) {
    audit_device($device, $user, $pass, $logfh, $timeout);
}

close $logfh;
print "[✓] Audit complete. Results written to $logfile\n";

#----------- SUBROUTINES -----------

sub audit_device {
    my ($device, $user, $pass, $logfh, $timeout) = @_;
    
    print "[*] Auditing $device...\n";
    log_msg($logfh, "\n" . "=" x 70);
    log_msg($logfh, "Device: $device | Timestamp: " . scalar localtime);
    log_msg($logfh, "=" x 70);
    
    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $device,
            user     => $user,
            password => $pass,
            timeout  => $timeout,
        );
        $ssh->login() or die "Login failed\n";
    } or do {
        my $error = $@ || "Unknown error";
        log_msg($logfh, "[ERROR] SSH connection failed: $error");
        print "[✗] $device: Connection failed\n";
        return;
    };
    
    my $route_output = '';
    eval {
        $ssh->send('show ip route');
        $route_output = $ssh->read_all();
        $ssh->close();
    } or do {
        my $error = $@ || "Unknown error";
        log_msg($logfh, "[ERROR] Route retrieval failed: $error");
        print "[✗] $device: Command execution failed\n";
        $ssh->close() if $ssh;
        return;
    };
    
    # Parse routing table for critical routes
    my %route_found = ();
    foreach my $line (split /\n/, $route_output) {
        foreach my $route (keys %CRITICAL_ROUTES) {
            if ($line =~ /\Q$route\E/) {
                $route_found{$route} = 1;
                log_msg($logfh, "[✓] Found: $route ($CRITICAL_ROUTES{$route})");
            }
        }
    }
    
    # Report missing routes
    my $missing_count = 0;
    foreach my $route (keys %CRITICAL_ROUTES) {
        unless ($route_found{$route}) {
            log_msg($logfh, "[✗] MISSING: $route ($CRITICAL_ROUTES{$route})");
            $missing_count++;
        }
    }
    
    # Summary
    my $audit_result = $missing_count ? "FAILED" : "PASSED";
    log_msg($logfh, "\nAudit Result: $audit_result");
    if ($missing_count) {
        log_msg($logfh, "Missing routes: $missing_count");
        print "[✗] $device: FAILED ($missing_count missing)\n";
    } else {
        print "[✓] $device: PASSED\n";
    }
}

sub read_device_list {
    my ($filename) = @_;
    open my $fh, '<', $filename or die "Cannot open $filename: $!\n";
    my @devices = grep { chomp; $_ } <$fh>;
    close $fh;
    return @devices;
}

sub log_msg {
    my ($fh, $message) = @_;
    print $fh "$message\n";
    print "$message\n";
}

sub usage {
    return <<'EOF';
Usage: route_audit.pl [options]

Options:
  --host HOSTNAME     IP or hostname of single device to audit
  --file FILENAME     File containing list of devices (one per line)
  --user USERNAME     SSH username (required)
  --pass PASSWORD     SSH password (if not provided, will be prompted)
  --log LOGFILE       Output log file (default: route_audit.log)
  --timeout SECONDS   SSH connection timeout (default: 30)
  --help              Display this help message

Examples:
  ./route_audit.pl --host 10.1.1.1 --user admin --pass mypass123
  ./route_audit.pl --file routers.txt --user admin --log audit_results.log

Modify %CRITICAL_ROUTES hash in script to define routes to audit.
EOF
}
```