```perl
#!/usr/bin/perl
# =============================================================================
# Device CPU/Memory Health Monitor
# Purpose: Monitor CPU and memory utilization on network devices via SSH
# Usage: device_cpu_memory_monitor.pl --device <host> [--user user] [--pass pass] [--logfile file]
#        or: device_cpu_memory_monitor.pl --file devices.txt
# Device file format: hostname|username|password (one per line, # for comments)
# Prerequisites: Net::SSH::Expect perl module
# Example: perl device_cpu_memory_monitor.pl --file devices.txt --threshold 80 --logfile health.log
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::HiRes qw(time);

my ($device, $file, $user, $pass, $logfile, $timeout, $threshold);

GetOptions(
    'device=s'    => \$device,
    'file=s'      => \$file,
    'user=s'      => \$user,
    'pass=s'      => \$pass,
    'logfile=s'   => \$logfile,
    'timeout=i'   => \$timeout,
    'threshold=i' => \$threshold,
    'help'        => sub { usage(); exit(0); }
) or die "Error parsing command line options\n";

$timeout   //= 12;
$user      //= 'admin';
$pass      //= 'admin';
$threshold //= 80;

sub usage {
    print "Usage: device_cpu_memory_monitor.pl [OPTIONS]\n\n";
    print "Options:\n";
    print "  --device <host>       Target device hostname/IP\n";
    print "  --file <path>         File with device list (host|user|pass format)\n";
    print "  --user <username>     SSH username (default: admin)\n";
    print "  --pass <password>     SSH password (default: admin)\n";
    print "  --logfile <path>      Log file path (optional)\n";
    print "  --timeout <seconds>   SSH timeout in seconds (default: 12)\n";
    print "  --threshold <percent> Alert threshold for CPU/mem (default: 80)\n";
    print "  --help                Show this help message\n";
}

die "Error: Specify either --device or --file\n" unless $device || $file;

my @targets = ();

if ($device) {
    push @targets, [$device, $user, $pass];
} elsif ($file) {
    open my $fh, '<', $file or die "Cannot open file $file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^#/ || /^\s*$/;
        my ($h, $u, $p) = split /\|/;
        die "Invalid line format: $_\n" unless $h;
        push @targets, [$h, $u || $user, $p || $pass];
    }
    close $fh;
    die "No valid targets in $file\n" unless @targets;
}

my $logfh;
if ($logfile) {
    open $logfh, '>>', $logfile or warn "Cannot open logfile $logfile: $!\n";
}

sub log_output {
    my ($msg) = @_;
    print "$msg\n";
    print $logfh "$msg\n" if $logfh;
}

my $timestamp = scalar(localtime);
log_output("================== Device Health Monitor ==================");
log_output("[$timestamp] Started - Threshold: ${threshold}%");
log_output("Targets: " . scalar(@targets));
log_output("============================================================");

my ($checked, $alerts, $failed) = (0, 0, 0);

foreach my $target (@targets) {
    my ($host, $user, $pass) = @$target;
    my $start = time();
    
    my $ssh = eval {
        my $s = Net::SSH::Expect->new(
            host     => $host,
            user     => $user,
            password => $pass,
            timeout  => $timeout,
            raw_pty  => 1
        );
        $s->login() or die "Authentication failed\n";
        return $s;
    };
    
    if (!$ssh) {
        log_output("[$host] FAIL - Connection error: $@");
        $failed++;
        next;
    }
    
    $checked++;
    eval {
        $ssh->send("show processes cpu | include CPU");
        $ssh->waitfor('\$|#|>', 2);
        my $cpu_buf = $ssh->get_buffer();
        my $cpu_util = 0;
        if ($cpu_buf =~ /CPU utilization.*?(\d+)%/) {
            $cpu_util = $1;
        }
        
        $ssh->send("show memory | include Processor");
        $ssh->waitfor('\$|#|>', 2);
        my $mem_buf = $ssh->get_buffer();
        my $mem_util = 0;
        if ($mem_buf =~ /(\d+)\s*K\s*free.*?(\d+)\s*K\s*total/) {
            my ($free, $total) = ($1, $2);
            $mem_util = int(100 * ($total - $free) / $total) if $total > 0;
        }
        
        my $elapsed = sprintf("%.2f", time() - $start);
        my $cpu_status = $cpu_util >= $threshold ? "ALERT" : "GOOD";
        my $mem_status = $mem_util >= $threshold ? "ALERT" : "GOOD";
        
        if ($cpu_status eq "ALERT" || $mem_status eq "ALERT") {
            $alerts++;
        }
        
        log_output("[$host] CPU:$cpu_util% [$cpu_status] | MEM:$mem_util% [$mem_status] (${elapsed}s)");
        
        $ssh->send("exit");
        $ssh->close();
    };
    
    if ($@) {
        log_output("[$host] WARN - Command execution error: $@");
    }
}

log_output("============================================================");
log_output("[" . scalar(localtime) . "] Completed - Checked:$checked Failed:$failed Alerts:$alerts");
log_output("============================================================");

close $logfh if $logfh;
exit($failed > 0 ? 1 : 0);
```