```perl
#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::localtime;

=head1 Device CPU and Memory Utilization Monitor

Connects to Cisco IOS/IOS-XE devices via SSH and monitors CPU and memory utilization.
Logs results to file and STDOUT, alerts when thresholds are exceeded.

Usage:
  ./device_health_monitor.pl --host 192.168.1.1 --user admin --password secret [--log output.log]

Prerequisites:
  - Net::SSH::Expect Perl module
  - SSH access enabled on device
  - Appropriate credentials

=cut

my ($host, $user, $password, $logfile, $cpu_threshold, $mem_threshold, $port, $timeout);
$cpu_threshold = 80;
$mem_threshold = 85;
$port = 22;
$timeout = 15;

GetOptions(
    'host|h=s'        => \$host,
    'user|u=s'        => \$user,
    'password|p=s'    => \$password,
    'log|l=s'         => \$logfile,
    'cpu-threshold=i' => \$cpu_threshold,
    'mem-threshold=i' => \$mem_threshold,
    'port=i'          => \$port,
    'timeout=i'       => \$timeout,
    'help'            => sub { usage(); exit(0); }
) or die "Error parsing command line arguments\n";

usage() unless $host && $user && $password;

my $fh;
if ($logfile) {
    open($fh, '>>', $logfile) or die "Cannot open log file $logfile: $!";
}

sub log_msg {
    my ($msg) = @_;
    my $ts = scalar(localtime);
    my $output = "[$ts] $msg";
    print "$output\n";
    print $fh "$output\n" if $fh;
}

sub usage {
    print <<EOF;
Device CPU and Memory Utilization Monitor
Tracks CPU and memory usage on Cisco network devices

Usage: $0 --host <ip> --user <user> --password <pass> [options]

Required:
  --host, -h          Device IP address or hostname
  --user, -u          SSH username
  --password, -p      SSH password

Optional:
  --log, -l <file>    Log file path
  --cpu-threshold     CPU alert threshold (default: 80%)
  --mem-threshold     Memory alert threshold (default: 85%)
  --port              SSH port (default: 22)
  --timeout           SSH timeout in seconds (default: 15)
  --help              Show this message

Example:
  $0 --host 10.0.0.1 --user netadmin --password secret123 --log health.log

EOF
}

sub connect_ssh {
    my ($ip, $user, $pass, $p, $t) = @_;
    my $ssh;
    
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $ip,
            password => $pass,
            user     => $user,
            port     => $p,
            timeout  => $t,
            raw_pty  => 1,
        );
        $ssh->connect() or die "SSH connection refused";
        $ssh->read_until('>', $t);
    };
    
    if ($@) {
        log_msg("ERROR: Cannot connect to $ip - $@");
        return undef;
    }
    return $ssh;
}

sub get_metrics {
    my ($ssh, $host) = @_;
    my ($cpu, $mem) = (undef, undef);
    
    eval {
        $ssh->send('terminal length 0');
        $ssh->read_until('>', $timeout);
        
        $ssh->send('show processes cpu | include CPU');
        my $cpu_data = $ssh->read_until('>', $timeout);
        
        if ($cpu_data =~ /CPU utilization for five seconds:\s*(\d+)%/) {
            $cpu = $1;
        }
        
        $ssh->send('show memory statistics | include Processor');
        my $mem_data = $ssh->read_until('>', $timeout);
        
        if ($mem_data =~ /Processor\s+\d+\s+(\d+)\s+\d+\s+(\d+)/) {
            my ($used, $total) = ($1, $2);
            $mem = int(($used / $total) * 100) if $total > 0;
        }
    };
    
    if ($@) {
        log_msg("ERROR: Failed to retrieve metrics - $@");
        return (undef, undef);
    }
    
    return ($cpu, $mem);
}

log_msg("Starting health check for $host");

my $ssh = connect_ssh($host, $user, $password, $port, $timeout);
exit(1) unless $ssh;

my ($cpu, $mem) = get_metrics($ssh, $host);

if (defined $cpu && defined $mem) {
    log_msg("METRICS: $host CPU=$cpu% Memory=$mem%");
    
    my @issues;
    push @issues, "CPU $cpu% exceeds threshold $cpu_threshold%" if $cpu >= $cpu_threshold;
    push @issues, "Memory $mem% exceeds threshold $mem_threshold%" if $mem >= $mem_threshold;
    
    if (@issues) {
        log_msg("ALERT: " . join(", ", @issues));
    } else {
        log_msg("STATUS: $host healthy - all metrics within thresholds");
    }
} else {
    log_msg("ERROR: Unable to collect metrics from $host");
}

eval { $ssh->close(); };
close($fh) if $fh;
exit(0);
```