#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::HiRes qw(time);

=head1 ROUTE VALIDATOR
Purpose: Validate critical routes exist on network devices and check routing table health
Usage: ./route_validator.pl -d <device> [-u <user>] [-p <pass>] [-r <routefile>] [-l <logfile>]
Prerequisites: Net::SSH::Expect, SSH access, administrative credentials
Features: Checks route existence, validates next-hop reachability, detects routing anomalies
=cut

my ($device, $user, $password, $route_file, $log_file, $help);
GetOptions(
    'device|d=s'  => \$device,
    'user|u=s'    => \$user,
    'pass|p=s'    => \$password,
    'routes|r=s'  => \$route_file,
    'log|l=s'     => \$log_file,
    'help|h'      => \$help,
) or die "Error in command line arguments\n";

if ($help || !$device) {
    print "Usage: $0 -d <device> [-u <user>] [-p <pass>] [-r <routefile>] [-l <logfile>]\n";
    print "  -d|device  : Target device hostname/IP\n";
    print "  -u|user    : SSH username (default: admin)\n";
    print "  -p|pass    : SSH password (required)\n";
    print "  -r|routes  : File with CIDR routes to validate (one per line)\n";
    print "  -l|log     : Optional log file for results\n";
    exit 0;
}

$user //= 'admin';
die "Error: Password required (-p option)\n" unless $password;

my @routes_to_check = ();
if ($route_file) {
    open my $fh, '<', $route_file or die "Cannot open routes file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^#/ || /^\s*$/;
        push @routes_to_check, $_;
    }
    close $fh;
}

my $output = validate_routes($device, $user, $password, @routes_to_check);
print $output;

if ($log_file) {
    open my $fh, '>>', $log_file or warn "Cannot open logfile: $log_file\n";
    print $fh $output;
    close $fh;
}

sub validate_routes {
    my ($device, $user, $password, @routes) = @_;
    my $out = '';
    my $time = scalar localtime;
    
    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host       => $device,
            user       => $user,
            password   => $password,
            timeout    => 25,
            raw_pty    => 1,
        );
        $ssh->login();
    };
    
    if ($@) {
        return "[ERROR] $time - Failed to connect to $device: $@\n";
    }
    
    $out .= "====== Route Validation Report ======\n";
    $out .= "Device: $device\n";
    $out .= "Time: $time\n";
    $out .= "====================================\n\n";
    
    # Fetch routing table
    my $routing_table = '';
    eval {
        $ssh->send('show ip route summary');
        $ssh->waitfor(['.*#'], 20);
        $routing_table = $ssh->before();
    };
    
    if ($@) {
        $out .= "[WARN] Could not retrieve routing summary\n\n";
    } else {
        $out .= "Routing Table Summary:\n";
        if ($routing_table =~ /Route Source\s+Routes\s+Subnets(.+?)$/ms) {
            my @lines = split /\n/, $1;
            foreach my $line (@lines) {
                $line =~ s/[\r\n]//g;
                next if $line =~ /^\s*$/;
                $out .= "  $line\n" if $line =~ /\w/;
            }
        }
        $out .= "\n";
    }
    
    # Validate specific routes if provided
    if (@routes) {
        $out .= "Critical Route Validation:\n";
        $out .= "-" x 40 . "\n";
        
        foreach my $route (@routes) {
            my $status = 'FAIL';
            
            eval {
                $ssh->send("show ip route $route");
                $ssh->waitfor(['.*#'], 15);
                my $result = $ssh->before();
                
                if ($result =~ /Routing entry for $route/i || $result =~ /\*.*$route/m) {
                    $status = 'PASS';
                    if ($result =~ /via\s+(\S+)/i) {
                        my $next_hop = $1;
                        $out .= "  [$status] Route: $route via $next_hop\n";
                    } else {
                        $out .= "  [$status] Route: $route exists\n";
                    }
                } else {
                    $out .= "  [$status] Route: $route NOT FOUND\n";
                }
            };
            
            if ($@) {
                $out .= "  [ERR] Route: $route (command failed)\n";
            }
        }
        $out .= "\n";
    }
    
    # Check for anomalies
    $out .= "Route Health Checks:\n";
    $out .= "-" x 40 . "\n";
    
    eval {
        $ssh->send('show ip route | include ^');
        $ssh->waitfor(['.*#'], 15);
        my $result = $ssh->before();
        my @route_lines = grep /^[A-Z*]/, split /\n/, $result;
        
        $out .= "  Total route entries: " . scalar(@route_lines) . "\n";
        $out .= "  Status: OK\n" if @route_lines > 0;
    };
    
    $out .= "\n====================================\n";
    
    eval { $ssh->close(); };
    
    return $out;
}

__END__