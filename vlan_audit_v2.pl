#!/usr/bin/perl
=head1 NAME
device_neighbor_connectivity.pl - Audit neighbor reachability from network device

=head1 DESCRIPTION
Connects to a network device via SSH and performs ping tests to verify connectivity
to neighbor devices. Reports reachability status, packet loss, and response times.
Useful for validating network paths from the device's perspective and troubleshooting
connectivity issues between network nodes.

=head1 USAGE
device_neighbor_connectivity.pl -device <ip|hostname> -targets <file|list> [options]

Examples:
  device_neighbor_connectivity.pl -device 10.1.1.1 -targets 10.1.1.2,10.1.1.3,10.1.1.4
  device_neighbor_connectivity.pl -device core1 -targets neighbors.txt -log audit.log
  device_neighbor_connectivity.pl -device 192.168.1.1 -targets targets.txt -user admin -pass mypass

=head1 PREREQUISITES
- Perl module: Net::SSH::Expect (install via: cpan Net::SSH::Expect)
- SSH access to target network device
- Target device must support 'ping <ip> count 4' command

=head1 OPTIONS
  -device <ip>      Target device IP or hostname (required)
  -targets <source> Comma-separated IP list or file path (required)
  -user <username>  SSH username (default: admin)
  -pass <password>  SSH password (default: admin)
  -log <file>       Append results to log file (optional)
  -timeout <sec>    SSH timeout in seconds (default: 30)

=cut

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Localtime;

my ($device, $targets_src, $user, $pass, $logfile, $timeout, $help);

GetOptions(
    'device=s'  => \$device,
    'targets=s' => \$targets_src,
    'user=s'    => \$user,
    'pass=s'    => \$pass,
    'log=s'     => \$logfile,
    'timeout=i' => \$timeout,
    'help'      => \$help,
) or die "Error in command line arguments\n";

if ($help || !$device || !$targets_src) {
    print "Usage: $0 -device <ip> -targets <list|file> [-user user] [-pass pass] [-log file]\n";
    exit $help ? 0 : 1;
}

$user    ||= 'admin';
$pass    ||= 'admin';
$timeout ||= 30;

my @targets = parse_targets($targets_src);
die "Error: No valid target IPs found\n" unless @targets;

my $timestamp = get_timestamp();
print "=== Device Neighbor Connectivity Audit ===\n";
print "Device: $device | Targets: " . scalar(@targets) . " | Time: $timestamp\n";
print "-" x 70 . "\n";

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log file $logfile: $!\n";
    print $log_fh "\n=== Connectivity Audit - $timestamp ===\n";
    print $log_fh "Device: $device\n";
}

my $ssh;
eval {
    $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $user,
        password => $pass,
        timeout  => $timeout,
        raw_pty  => 1,
    );
    $ssh->login();
};

if (!$ssh || $@) {
    my $msg = "ERROR: Cannot connect to $device: $@";
    print "$msg\n";
    print $log_fh "$msg\n" if $log_fh;
    close($log_fh) if $log_fh;
    exit 1;
}

my ($up_count, $down_count) = (0, 0);

foreach my $target (@targets) {
    my $result = ping_target($ssh, $target);
    
    if ($result->{reachable}) {
        printf("%-18s UP    | Loss: %3d%% | RTT: %7s ms\n",
            $target, $result->{loss}, $result->{rtt} // 'N/A');
        print $log_fh "$target UP (loss: $result->{loss}%, rtt: $result->{rtt}ms)\n" if $log_fh;
        $up_count++;
    } else {
        printf("%-18s DOWN  | Loss: 100%% | Unreachable\n", $target);
        print $log_fh "$target DOWN (unreachable)\n" if $log_fh;
        $down_count++;
    }
}

eval { $ssh->close(); };

print "-" x 70 . "\n";
printf("Result: %d reachable, %d unreachable\n", $up_count, $down_count);
print $log_fh "Summary: $up_count reachable, $down_count unreachable\n" if $log_fh;

close($log_fh) if $log_fh;
exit($down_count > 0 ? 1 : 0);

sub parse_targets {
    my ($source) = @_;
    my @ips;
    
    if (-f $source) {
        open(my $fh, '<', $source) or die "Cannot read $source: $!\n";
        while (my $line = <$fh>) {
            chomp($line);
            $line =~ s/#.*//;
            $line =~ s/^\s+|\s+$//g;
            if ($line && $line =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
                push @ips, $line;
            }
        }
        close($fh);
    } else {
        foreach my $ip (split /,/, $source) {
            $ip =~ s/^\s+|\s+$//g;
            if ($ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
                push @ips, $ip;
            }
        }
    }
    
    return @ips;
}

sub ping_target {
    my ($ssh, $target) = @_;
    my $result = {
        reachable => 0,
        loss      => 100,
        rtt       => undef,
    };
    
    eval {
        $ssh->send("ping $target count 4");
        my $output = '';
        sleep 1;
        
        for (my $i = 0; $i < 5; $i++) {
            last if $output =~ /\d+\s+packets?\s+(transmitted|sent)/i;
            $output .= $ssh->read_all();
            sleep 1 if $i < 4;
        }
        
        if ($output =~ /(\d+)\s+packets?\s+transmitted.*?(\d+)\s+(?:packets?\s+)?received/i) {
            my ($sent, $received) = ($1, $2);
            $result->{loss} = $sent > 0 ? int((($sent - $received) / $sent) * 100) : 100;
            $result->{reachable} = 1 if $received > 0;
        }
        
        if ($output =~ /(?:round.?trip\s+)?min\/avg\/max[^=]*=\s*[\d.]+\/([\d.]+)\/[\d.]+/i) {
            $result->{rtt} = int($1);
        } elsif ($output =~ /average\s*=\s*([\d.]+)/i) {
            $result->{rtt} = int($1);
        }
    };
    
    return $result;
}

sub get_timestamp {
    my $t = localtime;
    return sprintf("%04d-%02d-%02d %02d:%02d:%02d",
        $t->year() + 1900, $t->mon() + 1, $t->mday(),
        $t->hour(), $t->min(), $t->sec());
}