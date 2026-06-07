#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::HiRes qw(time);

=head1 NAME
acl_effectiveness_monitor.pl - Monitor ACL hit statistics on network devices

=head1 DESCRIPTION
Connects to Cisco IOS/IOS-XE devices via SSH and reports ACL statistics,
showing which ACLs are being matched and which may be inactive. Helps identify
unused rules and optimize security policies.

=head1 USAGE
acl_effectiveness_monitor.pl -h 192.168.1.1 -u admin -p password
acl_effectiveness_monitor.pl -f devices.txt -u admin -p password -l acl_stats.log

=head1 REQUIREMENTS
Net::SSH::Expect Perl module, SSH access to devices, valid credentials

=cut

my ($host, $file, $user, $pass, $log_file);

GetOptions(
    'h|host=s' => \$host,
    'f|file=s' => \$file,
    'u|user=s' => \$user,
    'p|pass=s' => \$pass,
    'l|log=s'  => \$log_file,
) or die "Error in command line arguments\n";

die "Usage: $0 -h <host> OR -f <file> -u <user> -p <password>\n" 
    unless (($host || $file) && $user && $pass);

my @devices = ();
if ($host) {
    @devices = ($host);
} else {
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    @devices = map { chomp; $_ } <$fh>;
    close $fh;
}

my $logfh;
if ($log_file) {
    open $logfh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

foreach my $device (@devices) {
    next unless $device;
    my $result = check_acl_stats($device, $user, $pass);
    print $result;
    print $logfh $result if $logfh;
}

close $logfh if $logfh;

sub check_acl_stats {
    my ($device, $username, $password) = @_;
    my $output = "=== ACL Stats: $device @ ".scalar(localtime)." ===\n";
    
    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host      => $device,
            password  => $password,
            user      => $username,
            raw_pty   => 1,
            timeout   => 20,
        );
    };
    
    if ($@) {
        $output .= "ERROR: Connection failed - $@\n\n";
        return $output;
    }
    
    eval {
        $ssh->login();
    };
    
    if ($@) {
        $output .= "ERROR: Authentication failed - $@\n\n";
        return $output;
    }
    
    my $result;
    eval {
        $ssh->send("show ip access-list\n");
        $result = $ssh->read_all(3);
    };
    
    if ($@ || !$result) {
        $output .= "ERROR: Command execution failed - $@\n\n";
        eval { $ssh->close(); };
        return $output;
    }
    
    if ($result =~ /^Error|^\s+\^|Invalid input/i) {
        $output .= "WARNING: No ACLs found or command not supported\n\n";
        eval { $ssh->close(); };
        return $output;
    }
    
    my %acl_stats = ();
    my $current_acl = '';
    
    foreach my $line (split /\n/, $result) {
        if ($line =~ /^Extended IP access list (\S+)/) {
            $current_acl = $1;
            $acl_stats{$current_acl} = { lines => 0, matches => 0 };
        } elsif ($current_acl && $line =~ /(\d+)\s+(permit|deny).*match/) {
            $acl_stats{$current_acl}{lines}++;
            $acl_stats{$current_acl}{matches}++ if $line =~ /match/;
        } elsif ($current_acl && $line =~ /(\d+)\s+(permit|deny)/) {
            $acl_stats{$current_acl}{lines}++;
        }
    }
    
    foreach my $acl (sort keys %acl_stats) {
        my $stats = $acl_stats{$acl};
        $output .= sprintf("  ACL: %-30s Rules: %3d  Matched: %s\n",
                          $acl, $stats->{lines}, 
                          $stats->{matches} ? "Yes" : "No");
    }
    
    eval { $ssh->close(); };
    
    $output .= "\n";
    return $output;
}