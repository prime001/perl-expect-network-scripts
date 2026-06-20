```perl
#!/usr/bin/perl
use strict;
use warnings;
use Expect;
use Getopt::Long;
use File::Spec;
use POSIX qw(strftime);

# Configuration Snapshot Capture Tool
# Purpose: SSH to network devices, capture timestamped show command outputs for comparison and auditing
# Usage: ./device_snapshot.pl --host 10.0.0.1 --user admin --pass secret --output ./snapshots
# 
# Useful for: configuration baselines, before/after change comparison, compliance documentation,
# troubleshooting configuration drift
# 
# Prerequisites: Net::SSH::Expect module, SSH access, device credentials

my %opts = (timeout => 30, port => 22, output => './snapshots');

GetOptions(
    'host=s'      => \$opts{host},
    'file=s'      => \$opts{file},
    'user=s'      => \$opts{user},
    'pass=s'      => \$opts{pass},
    'timeout=i'   => \$opts{timeout},
    'port=i'      => \$opts{port},
    'output=s'    => \$opts{output},
    'commands=s'  => \$opts{commands},
) or die "Error in options\n";

unless (($opts{host} || $opts{file}) && $opts{user}) {
    print "USAGE: $0 --host <device> --user <user> --pass <password> [--output <dir>]\n";
    print "       $0 --file <device_list> --user <user> --pass <password> [--output <dir>]\n";
    print "OPTIONS:\n";
    print "  --output <dir>     Output directory (default: ./snapshots)\n";
    print "  --commands <cmds>  Comma-separated commands (default: version,running-config,interfaces)\n";
    print "  --timeout <sec>    SSH timeout (default: 30)\n";
    exit 1;
}

mkdir $opts{output} unless -d $opts{output};

my @devices = $opts{host} ? ($opts{host}) : ();
if ($opts{file}) {
    open my $fh, '<', $opts{file} or die "Cannot open $opts{file}: $!\n";
    while (<$fh>) { chomp; push @devices, $_ if $_ && !/^#/; }
    close $fh;
}

my @commands = $opts{commands}
    ? split(/,/, $opts{commands})
    : qw(show version show running-config show interfaces brief);

sub snapshot_device {
    my ($device) = @_;
    
    my $ts = strftime("%Y%m%d_%H%M%S", localtime);
    my $file = File::Spec->catfile($opts{output}, "${device}_${ts}.txt");
    
    print "[" . scalar(localtime) . "] Capturing: $device... ";
    
    open my $fh, '>', $file or die "Cannot write $file: $!\n";
    
    my $exp = Expect->new();
    $exp->log_stdout(0);
    
    eval {
        $exp->spawn("ssh", "-p", $opts{port}, "-o", "StrictHostKeyChecking=no",
                    "-o", "ConnectTimeout=$opts{timeout}",
                    "$opts{user}\@$device")
            or die "SSH failed: $!";
        
        $exp->expect($opts{timeout},
            [ 'assword:', sub { $_[0]->send("$opts{pass}\n"); exp_continue; } ],
            [ 'yes/no',  sub { $_[0]->send("yes\n"); exp_continue; } ],
            [ qr/[>#]/, sub { 1; } ],
        ) or die "Auth timeout/failed";
        
        print $fh "Snapshot: $device\n";
        print $fh "Time: " . scalar(localtime) . "\n";
        print $fh "=" x 70 . "\n\n";
        
        foreach my $cmd (@commands) {
            $exp->send("$cmd\n");
            $exp->expect($opts{timeout}, [ qr/[>#]/ ]);
            
            print $fh ">>> $cmd\n";
            print $fh "-" x 70 . "\n";
            print $fh $exp->before() . "\n\n";
        }
        
        $exp->send("exit\n");
        $exp->soft_close();
        close $fh;
        
        print "OK\n";
        return 1;
    };
    
    if ($@) {
        print "FAILED ($@)\n";
        print $fh "ERROR: $@\n";
        close $fh;
        return 0;
    }
    
    return 0;
}

print "=" x 70 . "\n";
print "Device Configuration Snapshot Tool\n";
print "Output: $opts{output}\n";
print "Devices: " . scalar(@devices) . "\n";
print "Commands: " . join(", ", @commands) . "\n";
print "=" x 70 . "\n\n";

my ($ok, $fail) = (0, 0);
foreach my $device (@devices) {
    snapshot_device($device) ? $ok++ : $fail++;
}

print "\n" . "=" x 70 . "\n";
print "Results: $ok succeeded, $fail failed\n";
print "=" x 70 . "\n";

exit ($fail > 0 ? 1 : 0);
```