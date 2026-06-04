```perl
#!/usr/bin/perl
=head1 DEVICE HEALTH CHECK SCRIPT

Purpose:
  Connects to network devices via SSH and captures system health metrics.
  Reports uptime, CPU/memory utilization, and interface errors.

Usage:
  ./device_health_check.pl <device_ip>
  ./device_health_check.pl -d <device_ip> -u <username> -p <password>
  ./device_health_check.pl -f devices.txt

Prerequisites:
  - Net::SSH::Expect Perl module
  - SSH access to target devices (Cisco IOS/IOS-XE/NX-OS)
  - Valid credentials (prompted if not provided)

Output:
  - Formatted console output with health metrics
  - Timestamped log file (device_health_YYYYMMDD_HHMMSS.log)
  - Errors and failures logged with context

=cut

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Localtime;
use File::Spec;

my ($device, $username, $password, $input_file, $logfile);
my $timeout = 30;
my $verbose = 0;

GetOptions(
    'd|device=s'  => \$device,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'f|file=s'    => \$input_file,
    'l|log=s'     => \$logfile,
    'v|verbose'   => \$verbose,
    'h|help'      => \&usage,
) or usage();

# Validate input
unless ($device || $input_file) {
    print STDERR "Error: Specify device with -d or device list with -f\n";
    usage();
}

# Setup log file
unless ($logfile) {
    my ($sec, $min, $hour, $mday, $mon, $year) = localtime(time);
    $logfile = sprintf("device_health_%04d%02d%02d_%02d%02d%02d.log",
        $year + 1900, $mon + 1, $mday, $hour, $min, $sec);
}

open(my $log_fh, '>>', $logfile) or die "Cannot open log $logfile: $!\n";
sub log_msg {
    my $msg = shift;
    my $ts = scalar(localtime());
    print $log_fh "[$ts] $msg\n";
    print "$msg\n" if $verbose;
}

log_msg("=== Device Health Check Started ===");

# Get credentials
unless ($username) {
    print "SSH Username: ";
    chomp($username = <STDIN>);
    $username or die "Username required\n";
}
unless ($password) {
    print "SSH Password: ";
    system("stty", "-echo");
    chomp($password = <STDIN>);
    system("stty", "echo");
    print "\n";
    $password or die "Password required\n";
}

# Build device list
my @devices;
if ($input_file) {
    open(my $fh, '<', $input_file) or die "Cannot open $input_file: $!\n";
    @devices = grep { chomp; $_ && !/^\s*#/ } <$fh>;
    close($fh);
} else {
    @devices = ($device);
}

# Check each device
my $success_count = 0;
my $failure_count = 0;

foreach my $target (@devices) {
    $target =~ s/\s+//g;
    next unless $target;
    
    if (check_device($target, $username, $password, $log_fh)) {
        $success_count++;
    } else {
        $failure_count++;
    }
}

log_msg("=== Check Complete: $success_count successful, $failure_count failed ===");
close($log_fh);

print "\nLog file: $logfile\n";
exit($failure_count ? 1 : 0);

sub check_device {
    my ($ip, $user, $pass, $log) = @_;
    
    print "\n" . "─" x 60 . "\n";
    print "Device: $ip\n";
    
    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $ip,
            user     => $user,
            password => $pass,
            timeout  => $timeout,
            raw_pty  => 1,
        );
        $ssh->login();
    };
    
    if ($@) {
        my $error = "Connection failed: $@";
        print "✗ $error\n";
        log_msg("ERROR ($ip): $error");
        return 0;
    }
    
    # Suppress pagination
    $ssh->send("terminal length 0");
    $ssh->waitfor('>', $timeout) or do {
        log_msg("TIMEOUT ($ip): terminal config");
        return 0;
    };
    
    # Get uptime
    $ssh->send("show version | include uptime");
    my $uptime_raw = $ssh->read_all();
    
    my $uptime = "Unknown";
    if ($uptime_raw =~ /uptime is\s+(.+?)[\r\n]/) {
        $uptime = $1;
    }
    print "Uptime: $uptime\n";
    
    # Get CPU
    $ssh->send("show processes cpu | include CPU utilization");
    my $cpu_raw = $ssh->read_all();
    
    my $cpu = "N/A";
    if ($cpu_raw =~ /CPU utilization.*?(\d+)%/) {
        $cpu = "$1%";
    }
    print "CPU: $cpu\n";
    
    # Get memory
    $ssh->send("show memory | include Processor");
    my $mem_raw = $ssh->read_all();
    
    my $memory = "N/A";
    if ($mem_raw =~ /(\d+)K\s+total.*?(\d+)K\s+free/) {
        my $total = $1;
        my $free = $2;
        my $used_pct = int(100 * ($total - $free) / $total);
        $memory = "${used_pct}% used";
    }
    print "Memory: $memory\n";
    
    # Check interfaces
    $ssh->send("show interface summary");
    my $if_raw = $ssh->read_all();
    
    my $if_status = "OK";
    if ($if_raw =~ /(\d+).*error/) {
        $if_status = "⚠ $1 with errors";
    }
    print "Interfaces: $if_status\n";
    
    eval { $ssh->send("exit"); $ssh->close(); };
    
    print "✓ Check complete\n";
    log_msg("SUCCESS ($ip): Uptime=$uptime CPU=$cpu Memory=$memory");
    return 1;
}

sub usage {
    print <<'EOF';
DEVICE HEALTH CHECK - SSH Network Device Monitor

Usage: device_health_check.pl [options]

Options:
  -d, --device <IP>    Single device IP or hostname
  -f, --file <FILE>    File with device list (one per line, # for comments)
  -u, --user <NAME>    SSH username (prompted if omitted)
  -p, --pass <PASS>    SSH password (prompted if omitted)
  -l, --log <FILE>     Log file (auto-generated if omitted)
  -v, --verbose        Verbose output
  -h, --help           Show this help

Examples:
  device_health_check.pl -d 192.168.1.1
  device_health_check.pl -f devices.txt -u netadmin
  device_health_check.pl -d core-router -p mypass123

EOF
    exit 0;
}
```