```perl
#!/usr/bin/perl
use strict;
use warnings;
use Expect;
use Getopt::Long;
use Time::HiRes qw(time);

=head1 NAME
device_reachability.pl - Network device reachability and SSH connectivity monitor

=head1 SYNOPSIS
device_reachability.pl [OPTIONS] device_ip
device_reachability.pl -f devices.txt -u admin -l reach_report.log

=head1 DESCRIPTION
Monitors network device reachability via SSH, verifies authentication,
collects device uptime information, and generates connectivity reports.

=head1 OPTIONS
  -f, --file FILE      Read device list from file (one per line)
  -u, --user USER      SSH username (default: admin)
  -p, --pass PASS      SSH password (prompts if omitted)
  -l, --log FILE       Output log file (default: device_reach.log)
  -t, --timeout SEC    SSH connection timeout (default: 20 seconds)
=cut

my ($device, $file, $user, $pass, $log_file, $timeout);

GetOptions(
    'file|f=s'      => \$file,
    'user|u=s'      => \$user,
    'pass|p=s'      => \$pass,
    'log|l=s'       => \$log_file,
    'timeout|t=i'   => \$timeout,
) or die "Invalid command line arguments\n";

$device = shift @ARGV;
die "Usage: $0 device_ip or $0 -f device_file\n" unless $device || $file;

$user //= 'admin';
$log_file //= 'device_reach.log';
$timeout //= 20;

open(my $LOG, '>>', $log_file) or die "Cannot open $log_file: $!";
select($LOG); $| = 1; select(STDOUT); $| = 1;

sub timestamp {
    return scalar localtime;
}

sub log_msg {
    my $msg = shift;
    my $ts = timestamp();
    printf "%s - %s\n", $ts, $msg;
    printf $LOG "%s - %s\n", $ts, $msg;
}

sub get_password {
    system('stty', '-echo') if $^O !~ /MSWin/;
    print "SSH Password: ";
    chomp(my $pwd = <STDIN>);
    system('stty', 'echo') if $^O !~ /MSWin/;
    print "\n";
    return $pwd;
}

sub check_device {
    my ($host, $user, $pwd) = @_;
    my $start = time();
    my $success = 0;
    my $uptime_info = '';
    
    my $exp = Expect->new();
    $exp->log_stdout(0);
    
    unless ($exp->spawn("ssh -o ConnectTimeout=$timeout -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $user\@$host")) {
        log_msg("ERROR [$host]: SSH spawn failed - $!");
        return (0, -1, '');
    }
    
    $exp->timeout($timeout);
    my $authenticated = 0;
    
    eval {
        $exp->expect($timeout,
            [ qr/password/i, sub {
                $exp->send("$pwd\r");
                exp_continue;
            }],
            [ qr/[#>%]/, sub {
                $authenticated = 1;
            }],
            [ qr/(Permission denied|Authentication failed)/i, sub {
                die "Authentication failed for $host";
            }],
            [ qr/(refused|timeout|unreachable|unknown host)/i, sub {
                die "Connection failed: $&";
            }],
            [ timeout => sub {
                die "SSH timeout connecting to $host";
            }]
        );
    };
    
    if ($@) {
        log_msg("FAIL [$host]: $@");
        $exp->soft_close();
        return (0, -1, '');
    }
    
    if ($authenticated) {
        log_msg("OK [$host]: SSH authentication successful");
        $success = 1;
        
        $exp->send("terminal length 0\r");
        $exp->expect(2, qr/[#>%]/);
        
        $exp->send("show version | include uptime\r");
        eval {
            $exp->expect(5, [ qr/[#>%]/, sub { 
                $uptime_info = $exp->before(); 
                $uptime_info =~ s/[\r\n]+/ /g;
            }]);
        };
        
        if ($uptime_info =~ /\S/) {
            log_msg("UPTIME [$host]: $uptime_info");
        }
    }
    
    $exp->send("exit\r");
    $exp->soft_close();
    
    my $elapsed = sprintf("%.2f", time() - $start);
    return ($success, $elapsed, $uptime_info);
}

my @hosts;
if ($file) {
    open(my $fh, '<', $file) or die "Cannot open $file: $!";
    @hosts = grep { /\S/ } map { chomp; $_ } <$fh>;
    close($fh);
} else {
    @hosts = ($device);
}

$pass //= get_password();

log_msg("=" x 70);
log_msg("Device Reachability Monitor: " . scalar(@hosts) . " device(s)");
log_msg("=" x 70);

my ($reachable, $total) = (0, 0);
my @response_times;

foreach my $host (@hosts) {
    next unless $host =~ /\S/;
    $total++;
    my ($status, $time, $info) = check_device($host, $user, $pass);
    $reachable++ if $status;
    push(@response_times, $time) if $time > 0;
}

log_msg("=" x 70);
log_msg("SUMMARY: $reachable/$total devices reachable (" . int(100*$reachable/$total) . "%)");

if (@response_times) {
    my $sum = 0;
    $sum += $_ for @response_times;
    my $avg = sprintf("%.2f", $sum / @response_times);
    log_msg("Average SSH connection time: ${avg}s");
}

log_msg("=" x 70);
close($LOG);

exit($reachable == $total ? 0 : 1);
```