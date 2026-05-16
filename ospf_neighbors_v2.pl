```perl
#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::HiRes qw(time);
use POSIX qw(strftime);

=head1 OSPF Neighbor Flap Monitor

Monitors Cisco IOS/IOS-XE routers for OSPF neighbor state flapping and instability.
Detects rapid state transitions and generates alerts on neighbor state oscillation.

Usage:
  ospf_flap_monitor.pl <device> [--log <file>] [--interval <sec>] [--threshold <n>]

Arguments:
  device              IP address or hostname of router
  --log FILE          Optional log file for persistent monitoring
  --interval SECS     Check interval in seconds (default: 30)
  --threshold N       Flap threshold before alerting (default: 3 in 300s)

Prerequisites:
  - Net::SSH::Expect module installed
  - SSH access to device with credentials in SSH_USER/SSH_PASS env vars
  - Device running Cisco IOS/IOS-XE with OSPF enabled

=cut

my ($device, $logfile, $interval, $threshold);
GetOptions(
    'device=s'    => \$device,
    'log=s'       => \$logfile,
    'interval=i'  => \$interval,
    'threshold=i' => \$threshold,
) or die "Usage: $0 <device> [--log <file>] [--interval <sec>] [--threshold <n>]\n";

die "Device required\n" unless $device;

$interval  //= 30;
$threshold //= 3;

my $ssh_user = $ENV{SSH_USER} || 'admin';
my $ssh_pass = $ENV{SSH_PASS} or die "SSH_PASS not set\n";

my %neighbor_state;
my %flap_times;

sub log_output {
    my ($msg) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    print "[$ts] $msg\n";
    
    if ($logfile) {
        open my $fh, '>>', $logfile or warn "Cannot open $logfile: $!";
        print $fh "[$ts] $msg\n";
        close $fh;
    }
}

sub connect_ssh {
    my $ssh = Net::SSH::Expect->new(
        host      => $device,
        user      => $ssh_user,
        password  => $ssh_pass,
        raw_pty   => 1,
        timeout   => 10,
    );
    
    eval { $ssh->login() } or do {
        log_output("ERROR: SSH connection failed to $device: $@");
        return undef;
    };
    
    return $ssh;
}

sub get_neighbors {
    my ($ssh) = @_;
    return {} unless $ssh;
    
    my @output;
    eval {
        $ssh->send("show ip ospf neighbor");
        $ssh->waitfor('prompt', 5);
        @output = split /\n/, $ssh->exec("show ip ospf neighbor");
    } or do {
        log_output("ERROR: Failed to retrieve neighbors: $@");
        return {};
    };
    
    my %neighbors;
    foreach my $line (@output) {
        next unless $line =~ /^(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\w+)/;
        my ($rid, $ip, $state) = ($1, $2, $3);
        $neighbors{$rid} = { ip => $ip, state => $state };
    }
    
    return \%neighbors;
}

sub check_flapping {
    my ($neighbors) = @_;
    my $now = time();
    
    foreach my $rid (keys %$neighbors) {
        my $current_state = $neighbors->{$rid}{state};
        my $prev_state = $neighbor_state{$rid};
        
        if (defined $prev_state && $prev_state ne $current_state) {
            $flap_times{$rid} //= [];
            push @{$flap_times{$rid}}, $now;
            
            log_output("State change: Neighbor $rid: $prev_state -> $current_state");
            
            my @recent = grep { $now - $_ < 300 } @{$flap_times{$rid}};
            $flap_times{$rid} = \@recent;
            
            if (@recent >= $threshold) {
                log_output("ALERT: Neighbor $rid flapping (" . scalar(@recent) . 
                          " transitions in 5 minutes)");
            }
        }
        
        $neighbor_state{$rid} = $current_state;
    }
}

sub main {
    log_output("OSPF flap monitor started for $device (interval: ${interval}s, threshold: $threshold)");
    
    while (1) {
        my $ssh = connect_ssh();
        if ($ssh) {
            my $neighbors = get_neighbors($ssh);
            check_flapping($neighbors) if keys %$neighbors;
            $ssh->close();
        }
        
        sleep($interval);
    }
}

main();
```