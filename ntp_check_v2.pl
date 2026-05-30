```perl
#!/usr/bin/perl
=head1 NAME
device_reachability_test.pl - Test SSH connectivity to network devices

=head1 DESCRIPTION
Performs SSH connectivity testing against a list of network devices. Verifies
device availability and SSH responsiveness before running automation tasks.
Reports connection status, response time, and authentication results.

=head1 USAGE
  ./device_reachability_test.pl -d 192.168.1.1 -u admin -p password
  ./device_reachability_test.pl -f hosts.txt -u admin -p password -l results.log

=head1 OPTIONS
  -d, --device       Single device IP or hostname
  -f, --file         File with device list (one per line)
  -u, --username     SSH username
  -p, --password     SSH password
  -l, --logfile      Optional log file path
  -t, --timeout      SSH timeout in seconds (default: 5)
  --help             Show this message

=head1 PREREQUISITES
  - Net::SSH::Expect Perl module
  - Network connectivity to target devices
  - Valid SSH credentials

=cut

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Piece;
use Time::HiRes qw(time);

my ($device, $file, $user, $pass, $logfile, $timeout, $help);

GetOptions(
    'd|device=s'    => \$device,
    'f|file=s'      => \$file,
    'u|username=s'  => \$user,
    'p|password=s'  => \$pass,
    'l|logfile=s'   => \$logfile,
    't|timeout=i'   => \$timeout,
    'help'          => \$help,
) or die "Error in command line arguments\n";

if ($help || (!$device && !$file) || !$user || !$pass) {
    system("perldoc $0");
    exit 0;
}

$timeout ||= 5;

my @devices = $device ? ($device) : do {
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    my @list;
    while (<$fh>) {
        chomp;
        next if /^#/ || /^\s*$/;
        push @list, $_;
    }
    close $fh;
    @list;
};

open my $LOG, '>>', $logfile if $logfile;

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $LOG "$msg\n" if $logfile;
}

my $timestamp = localtime->strftime('%Y-%m-%d %H:%M:%S');
output("[$timestamp] Connectivity audit started - " . scalar(@devices) . " device(s)");
output("-" x 70);

my ($success, $failure) = (0, 0);

foreach my $host (@devices) {
    my $start_time = time();
    my $ssh;
    my $result = "UNREACHABLE";
    my $detail = "";
    
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $host,
            user     => $user,
            password => $pass,
            timeout  => $timeout,
            raw_pty  => 1,
        );
        
        $ssh->login() or die "SSH login failed";
        $result = "SUCCESS";
        $ssh->close();
    };
    
    if ($@) {
        my $error = $@;
        $error =~ s/\n/ /g;
        $error =~ s/\s+/ /g;
        $detail = $error;
    }
    
    my $elapsed = sprintf("%.2f", time() - $start_time);
    
    if ($result eq "SUCCESS") {
        output(sprintf("%-35s %-12s %6s", $host, $result, $elapsed . "s"));
        $success++;
    } else {
        output(sprintf("%-35s %-12s %6s  %s", $host, $result, $elapsed . "s", $detail));
        $failure++;
    }
}

output("-" x 70);
output(sprintf("Summary: %d successful, %d failed (%.1f%% availability)",
    $success, $failure, 
    $success ? ($success / ($success + $failure) * 100) : 0));
output("[$timestamp] Audit completed\n");

close $LOG if $logfile;
exit $failure ? 1 : 0;
```