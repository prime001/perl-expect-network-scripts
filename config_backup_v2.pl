```perl
#!/usr/bin/perl
# ACL Audit Script - Collects and analyzes Access Control Lists from network devices
# Purpose: Audit ACLs across network devices for policy compliance and configuration audit
# Usage: ./acl_audit.pl <device_ip> [--user username] [--pass password] [--log logfile]
# Prerequisites: Net::SSH::Expect module, SSH access to network devices
# Supports: Cisco IOS, IOS-XE, NX-OS devices

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::HiRes qw(time);

my $device = shift @ARGV or die "Usage: $0 <device_ip> [--user user] [--pass pass] [--log file]\n";
my ($username, $password, $logfile, $timeout) = ('admin', '', '', 15);

GetOptions(
    'user=s'    => \$username,
    'pass=s'    => \$password,
    'log=s'     => \$logfile,
    'timeout=i' => \$timeout,
) or die "Invalid options\n";

# Prompt for password if not provided
if (!$password) {
    print "Password for $username: ";
    system('stty', '-echo');
    chomp($password = <STDIN>);
    system('stty', 'echo');
    print "\n";
}

my $start_time = time();
my %results = (
    device => $device,
    status => 'UNKNOWN',
    timestamp => scalar(localtime()),
    acl_count => 0,
    total_rules => 0,
    ipv4_count => 0,
    ipv6_count => 0,
    empty_acls => 0,
);

# Establish SSH connection
my $ssh = eval {
    Net::SSH::Expect->new(
        host => $device,
        user => $username,
        password => $password,
        raw_pty => 1,
        timeout => $timeout,
    );
};

if (!$ssh || $@) {
    $results{status} = 'FAILED';
    $results{error} = "Connection failed: $@";
    output_results(\%results, time() - $start_time, $logfile);
    exit 1;
}

# Authenticate
eval { $ssh->login(); };
if ($@) {
    $results{status} = 'FAILED';
    $results{error} = "Authentication failed: $@";
    output_results(\%results, time() - $start_time, $logfile);
    exit 1;
}

# Collect ACL information
my $acl_data = '';
eval {
    $ssh->send('show access-lists');
    $acl_data = $ssh->read_all();
};

if ($@) {
    $results{status} = 'FAILED';
    $results{error} = "Command failed: $@";
    $ssh->close();
    output_results(\%results, time() - $start_time, $logfile);
    exit 1;
}

# Parse ACL output
my %acl_info = parse_acls($acl_data);
$results{acl_count} = scalar(keys %acl_info);

# Analyze ACLs
foreach my $acl (keys %acl_info) {
    my $rules = $acl_info{$acl}{rules} // 0;
    $results{total_rules} += $rules;
    
    if ($acl_info{$acl}{ipv6}) {
        $results{ipv6_count}++;
    } else {
        $results{ipv4_count}++;
    }
    
    $results{empty_acls}++ if $rules == 0;
}

$results{status} = 'SUCCESS';
$ssh->close();

output_results(\%results, time() - $start_time, $logfile);
exit 0;

sub parse_acls {
    my ($output) = @_;
    my %acls;
    my ($current_acl, $acl_type);
    
    foreach my $line (split /\n/, $output) {
        next if !$line || $line =~ /^\s*$/;
        
        if ($line =~ /^(Standard|Extended)\s+(IP|IPv4|IPv6)\s+access list\s+(\S+)/i) {
            $current_acl = $3;
            $acl_type = $2;
            $acls{$current_acl} = {
                type => $1,
                ipv6 => ($2 =~ /IPv6/i ? 1 : 0),
                rules => 0,
            };
        } elsif ($current_acl && $line =~ /^\s+\d+\s+(permit|deny)/i) {
            $acls{$current_acl}{rules}++;
        }
    }
    
    return %acls;
}

sub output_results {
    my ($results, $elapsed, $logfile) = @_;
    
    my $output = '';
    $output .= "=== ACL Audit Report ===\n";
    $output .= "Device: $results->{device}\n";
    $output .= "Status: $results->{status}\n";
    $output .= "Timestamp: $results->{timestamp}\n";
    $output .= sprintf("Duration: %.2fs\n\n", $elapsed);
    
    if ($results->{status} eq 'SUCCESS') {
        $output .= "ACL Count: $results->{acl_count}\n";
        $output .= "Total Rules: $results->{total_rules}\n";
        $output .= "IPv4 ACLs: $results->{ipv4_count}\n";
        $output .= "IPv6 ACLs: $results->{ipv6_count}\n";
        $output .= "Empty ACLs (warnings): $results->{empty_acls}\n";
    } else {
        $output .= "Error: $results->{error}\n";
    }
    
    print $output;
    
    if ($logfile) {
        open my $fh, '>>', $logfile or warn "Cannot open $logfile: $!\n";
        print $fh $output;
        close $fh;
    }
}
```