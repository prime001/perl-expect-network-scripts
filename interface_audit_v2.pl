```perl
#!/usr/bin/perl
use strict;
use warnings;
use Expect;
use Getopt::Long;
use Time::HiRes qw(time);
use POSIX qw(strftime);

=head1 device_health_monitor.pl

Collects real-time health metrics from network devices for anomaly detection.
Monitors CPU, memory, interface errors, and system uptime via SSH.

=head1 USAGE

./device_health_monitor.pl --device 192.168.1.1 --user admin --pass password [--log output.log]
./device_health_monitor.pl --file device_list.txt --baseline thresholds.conf [--log output.log]

=head1 DESCRIPTION

Connects to each device, collects key performance indicators, and alerts on:
- High CPU utilization
- High memory consumption
- Excessive interface errors
- Unusual system behavior

Useful for capacity planning, trend analysis, and early fault detection.

=head1 PREREQUISITES

Perl modules: Expect, Getopt::Long, Time::HiRes (all standard)
Network access to devices via SSH
Device credentials with "show" command permissions

=cut

my ($device, $user, $pass, $device_file, $baseline_file, $log_file, $timeout);
GetOptions(
    'device=s' => \$device,
    'user=s' => \$user,
    'pass=s' => \$pass,
    'file=s' => \$device_file,
    'baseline=s' => \$baseline_file,
    'log=s' => \$log_file,
    'timeout=i' => \$timeout,
) or die "Error in command line options\n";

$user ||= 'admin';
$pass ||= $ENV{DEVICE_PASSWORD} || 'admin';
$timeout ||= 5;
$log_file ||= 'device_health.log';
$baseline_file ||= 'health_baseline.conf';

die "Usage: $0 --device <ip> or --file <device_list>\n" 
    unless $device || $device_file;

my @devices = $device ? ($device) : read_device_list($device_file);
my %thresholds = load_thresholds($baseline_file);

open my $LOG, '>>', $log_file or die "Cannot open log $log_file: $!\n";
log_entry($LOG, "=== Health check started ===");

foreach my $host (@devices) {
    monitor_device($host, $user, $pass, \%thresholds, $LOG, $timeout);
}

log_entry($LOG, "=== Health check completed ===");
close($LOG);
print "[OK] Results logged to $log_file\n";

sub monitor_device {
    my ($host, $user, $pass, $thresholds, $log, $timeout) = @_;
    print "Checking $host... ";
    
    my $exp = Expect->new();
    $exp->log_stdout(0);
    
    my $start_time = time();
    my $connection_time;
    
    eval {
        $exp->spawn("ssh -o ConnectTimeout=$timeout -o StrictHostKeyChecking=no $user\@$host")
            or die "Cannot spawn SSH connection\n";
        
        $exp->expect($timeout, ['password:', qr/[#>$]\s*$/])
            or die "No prompt or password prompt within timeout\n";
        
        if ($exp->match() =~ /password/) {
            $exp->send("$pass\n");
            $exp->expect($timeout, ['#', '>', qr/\$\s*$/])
                or die "Authentication failed or no valid prompt\n";
        }
        
        $connection_time = time() - $start_time;
        
        my %metrics = collect_device_metrics($exp, $host, $timeout);
        evaluate_health_status($host, \%metrics, $thresholds, $log);
        
        $exp->send("exit\n");
        $exp->soft_close();
        
        print "OK (" . sprintf("%.2f", $connection_time) . "s)\n";
    };
    
    if ($@) {
        my $error = $@;
        chomp($error);
        print "FAILED\n";
        log_entry($LOG, "[ERROR] $host: $error");
    }
}

sub collect_device_metrics {
    my ($exp, $host, $timeout) = @_;
    my %metrics = (host => $host, timestamp => strftime('%Y-%m-%d %H:%M:%S', localtime));
    
    # Get uptime
    $exp->send("show version | grep -i uptime\n");
    $exp->expect($timeout, ['#', '>']);
    if ($exp->before() =~ /uptime\s+is\s+(.+?)[\r\n]/i) {
        $metrics{uptime} = $1;
    }
    
    # Get CPU utilization
    $exp->send("show processes cpu | include CPU\n");
    $exp->expect($timeout, ['#', '>']);
    if ($exp->before() =~ /(\d+)%/) {
        $metrics{cpu_percent} = $1;
    }
    
    # Get memory statistics
    $exp->send("show memory | include Processor\n");
    $exp->expect($timeout, ['#', '>']);
    if ($exp->before() =~ /(\d+)K\s+used/) {
        $metrics{memory_used_kb} = $1;
    }
    
    # Count interface errors
    $exp->send("show interfaces | include errors\n");
    $exp->expect($timeout, ['#', '>']);
    my $error_count = 0;
    while ($exp->before() =~ /(\d+)\s+errors/g) {
        $error_count += $1;
    }
    $metrics{total_errors} = $error_count;
    
    return %metrics;
}

sub evaluate_health_status {
    my ($host, $metrics, $thresholds, $log) = @_;
    my $cfg = $thresholds->{$host} || $thresholds->{DEFAULT};
    
    my @alerts;
    
    if (defined $metrics->{cpu_percent}) {
        if ($metrics->{cpu_percent} > $cfg->{cpu_critical}) {
            push @alerts, "CRITICAL CPU: $metrics->{cpu_percent}%";
        } elsif ($metrics->{cpu_percent} > $cfg->{cpu_warning}) {
            push @alerts, "WARNING CPU: $metrics->{cpu_percent}%";
        }
    }
    
    if (defined $metrics->{memory_used_kb}) {
        if ($metrics->{memory_used_kb} > $cfg->{memory_critical}) {
            push @alerts, "CRITICAL Memory: $metrics->{memory_used_kb}KB";
        } elsif ($metrics->{memory_used_kb} > $cfg->{memory_warning}) {
            push @alerts, "WARNING Memory: $metrics->{memory_used_kb}KB";
        }
    }
    
    if ($metrics->{total_errors} > $cfg->{error_threshold}) {
        push @alerts, "Interface errors: $metrics->{total_errors}";
    }
    
    if (@alerts) {
        print STDERR "  [ALERT] $_\n" for @alerts;
        log_entry($log, "[ALERT] $host: " . join(" | ", @alerts));
    } else {
        log_entry($log, "[OK] $host - CPU: $metrics->{cpu_percent}% " .
                        "Memory: $metrics->{memory_used_kb}KB Errors: $metrics->{total_errors}");
    }
}

sub read_device_list {
    my ($file) = @_;
    return unless $file && -e $file;
    
    open my $fh, '<', $file or die "Cannot open device list $file: $!\n";
    my @list = grep { /\S/ && !/^\s*#/ } <$fh>;
    chomp @list;
    close($fh);
    return @list;
}

sub load_thresholds {
    my ($file) = @_;
    my %cfg = (
        DEFAULT => {
            cpu_warning => 70,
            cpu_critical => 85,
            memory_warning => 75000,
            memory_critical => 90000,
            error_threshold => 50,
        }
    );
    
    return %cfg unless -e $file;
    
    open my $fh, '<', $file or return %cfg;
    my $current_device;
    
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        
        if (/^\[(.+?)\]/) {
            $current_device = $1;
            $cfg{$current_device} = { %{$cfg{DEFAULT}} };
        } elsif ($current_device && /^\s*(\w+)\s*=\s*(\d+)/) {
            $cfg{$current_device}{$1} = $2;
        }
    }
    
    close($fh);
    return %cfg;
}

sub log_entry {
    my ($fh, $message) = @_;
    my $timestamp = strftime('[%Y-%m-%d %H:%M:%S]', localtime);
    print $fh "$timestamp $message\n";
}
```