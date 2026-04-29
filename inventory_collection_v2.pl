```perl
#!/usr/bin/perl
=head1 NAME
device_access_auditor.pl - Verify SSH connectivity and authentication to network devices

=head1 SYNOPSIS
./device_access_auditor.pl -d <device> [OPTIONS]
./device_access_auditor.pl -f <device_list.txt> [OPTIONS]

=head1 DESCRIPTION
Audits SSH accessibility to network devices. Tests both key-based and password
authentication, validates shell access with diagnostic commands. Essential for
verifying device reachability before executing production automation scripts.
Reports which authentication methods work and identifies access failures.

=head1 OPTIONS
  -d, --device HOST       Single device IP or hostname
  -f, --file FILE         File with list of devices (one per line)
  -u, --username USER     SSH username (default: admin)
  -p, --password PASS     SSH password (uses key if not specified)
  -k, --keyfile PATH      SSH private key file (default: ~/.ssh/id_rsa)
  -t, --timeout SECS      SSH timeout in seconds (default: 15)
  -l, --logfile FILE      Write results to log file
  -q, --quick             Quick mode - test connection only
  -v, --verbose           Verbose output

=head1 PREREQUISITES
Net::SSH::Expect, Getopt::Long (core Perl modules)

=head1 AUTHOR
Network Engineering Automation Suite

=cut

use strict;
use warnings;
use Getopt::Long;
use Net::SSH::Expect;
use Time::HiRes qw(time);

my %opts = (
    username => 'admin',
    timeout  => 15,
    quick    => 0,
    verbose  => 0,
);

GetOptions(
    'file|f=s'     => \$opts{file},
    'device|d=s'   => \$opts{device},
    'username|u=s' => \$opts{username},
    'password|p=s' => \$opts{password},
    'keyfile|k=s'  => \$opts{keyfile},
    'timeout|t=i'  => \$opts{timeout},
    'logfile|l=s'  => \$opts{logfile},
    'quick|q'      => \$opts{quick},
    'verbose|v'    => \$opts{verbose},
) or die "Error in command line arguments\n";

die "Specify either --file or --device\n" unless $opts{file} || $opts{device};

my @devices;
if ($opts{device}) {
    push @devices, $opts{device};
} else {
    open my $fh, '<', $opts{file} or die "Cannot open $opts{file}: $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
}

my $logfh;
open $logfh, '>', $opts{logfile} or die "Cannot open logfile: $!\n" if $opts{logfile};

my ($passed, $failed, $warned) = (0, 0, 0);
my @results;

foreach my $device (@devices) {
    my $start = time;
    printf "[*] %-25s ", $device;
    
    my ($status, $msg, $auth_type) = test_device($device);
    my $elapsed = time - $start;
    
    if ($status eq 'PASS') {
        print "OK ";
        $passed++;
    } elsif ($status eq 'WARN') {
        print "WARN ";
        $warned++;
    } else {
        print "FAIL ";
        $failed++;
    }
    printf "(%.2fs)\n", $elapsed;
    
    push @results, {
        device => $device,
        status => $status,
        message => $msg,
        auth => $auth_type,
        time => $elapsed
    };
}

print "\n" . "="x60 . "\n";
print "SUMMARY: Passed=$passed  Warned=$warned  Failed=$failed\n";
print "="x60 . "\n";

if ($opts{verbose} || $opts{logfile}) {
    foreach my $r (@results) {
        my $line = sprintf("%s [%s] %s (auth: %s)",
            $r->{device}, $r->{status}, $r->{message}, $r->{auth});
        print "$line\n" if $opts{verbose};
        print $logfh "$line\n" if $logfh;
    }
}

close $logfh if $logfh;

sub test_device {
    my ($device) = @_;
    
    return ('FAIL', 'Invalid device name', 'none') unless $device;
    
    my $ssh = Net::SSH::Expect->new(
        host => $device,
        user => $opts{username},
        password => $opts{password} || '',
        timeout => $opts{timeout},
        ($opts{keyfile} ? (key_path => $opts{keyfile}) : ()),
    );
    
    my $auth_type = 'unknown';
    
    eval {
        $ssh->login();
        $auth_type = $opts{keyfile} ? 'key' : ($opts{password} ? 'password' : 'key');
    };
    
    return ('FAIL', "Connection error: $@", $auth_type) if $@;
    return ('FAIL', 'Authentication failed', $auth_type) unless $ssh->{_connected};
    
    if ($opts{quick}) {
        eval { $ssh->close() };
        return ('PASS', 'SSH access OK', $auth_type);
    }
    
    my $test_ok = 0;
    eval {
        my $output = $ssh->exec('show version 2>/dev/null || uname -a');
        $test_ok = 1 if $output && length($output) > 20;
    };
    
    eval { $ssh->close() };
    
    return ('FAIL', 'Command execution failed', $auth_type) unless $test_ok;
    return ('PASS', 'SSH and shell verified', $auth_type);
}
```