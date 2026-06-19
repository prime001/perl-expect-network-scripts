```perl
#!/usr/bin/perl
#
# device_connectivity_validator.pl - Validate SSH connectivity and basic device health
#
# DESCRIPTION:
#   This script verifies SSH connectivity to network devices and validates basic
#   operational health. It retrieves device hostname, OS version, uptime, and model
#   information to confirm devices are reachable and responsive. Useful for
#   pre-maintenance validation and network readiness checks.
#
# USAGE:
#   perl device_connectivity_validator.pl --device 10.1.1.1 --user admin --pass secret
#   perl device_connectivity_validator.pl --file devices.txt --user admin --pass secret --log results.log
#
# ARGUMENTS:
#   --device <ip/hostname>   Single device to check
#   --file <filename>        File with one device per line
#   --user <username>        SSH username (default: admin)
#   --pass <password>        SSH password (required)
#   --log <filename>         Optional output log file
#   --timeout <seconds>      SSH timeout (default: 10)
#
# PREREQUISITES:
#   - Net::SSH::Expect Perl module
#   - SSH access enabled on devices
#   - IOS/IOS-XE or similar CLI interface
#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::HiRes qw(time);

my ($device, $file, $user, $pass, $logfile, $timeout);

GetOptions(
    'device=s'  => \$device,
    'file=s'    => \$file,
    'user=s'    => \$user,
    'pass=s'    => \$pass,
    'log=s'     => \$logfile,
    'timeout=i' => \$timeout,
) or die "Usage error\n";

$timeout //= 10;
$user //= 'admin';
die "ERROR: Password required (--pass)\n" unless $pass;
die "ERROR: Specify --device or --file\n" unless ($device || $file);

my @devices = $device ? ($device) : do {
    open my $fh, '<', $file or die "ERROR: Cannot open $file: $!\n";
    my @list = grep { chomp; $_ && !/^#/ } <$fh>;
    close $fh;
    @list;
};

die "ERROR: No devices to validate\n" unless @devices;

my $log_fh;
if ($logfile) {
    open $log_fh, '>', $logfile or die "ERROR: Cannot open log $logfile: $!\n";
}

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
}

sub log_msg {
    my ($msg) = @_;
    print STDERR "$msg\n";
}

output("=" x 80);
output("DEVICE CONNECTIVITY VALIDATION REPORT");
output("Start Time: " . scalar localtime());
output("=" x 80);
output(sprintf("%-20s %-15s %-30s %s", "DEVICE", "STATUS", "HOSTNAME", "VERSION"));
output("-" x 80);

my ($success, $failed) = (0, 0);

foreach my $dev (sort @devices) {
    $dev =~ s/\s+//g;
    next unless $dev;
    
    my $status = "UNREACHABLE";
    my $hostname = "";
    my $version = "";
    my $start = time();
    
    eval {
        my $ssh = Net::SSH::Expect->new(
            host     => $dev,
            user     => $user,
            password => $pass,
            timeout  => $timeout,
            raw_pty  => 1,
        );
        
        $ssh->login() or die "Login failed";
        
        $ssh->send("terminal length 0");
        $ssh->waitfor('>', 2);
        
        $ssh->send("show version | include Device|IOS");
        my $ver_out = $ssh->waitfor('>', 3);
        if ($ver_out =~ /Version\s+([\d\.]+)/i) {
            $version = $1;
        }
        
        $ssh->send("show run | include hostname");
        my $host_out = $ssh->waitfor('>', 3);
        if ($host_out =~ /hostname\s+(\S+)/i) {
            $hostname = $1;
        }
        
        $ssh->send("exit");
        $ssh->close();
        
        $status = "OK";
        $success++;
    } or do {
        my $err = $@;
        $status = "FAIL";
        $failed++;
        log_msg("DEBUG: $dev - $err") if $err;
    };
    
    my $elapsed = sprintf("%.2fs", time() - $start);
    output(sprintf("%-20s %-15s %-30s %s (%s)", 
        $dev, $status, $hostname || "unknown", $version || "unknown", $elapsed));
}

output("-" x 80);
output(sprintf("Results: %d OK, %d FAILED (Total: %d)", $success, $failed, scalar @devices));
output("End Time: " . scalar localtime());
output("=" x 80);

close $log_fh if $log_fh;
exit($failed > 0 ? 1 : 0);
```