#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::HiRes qw(usleep);

=head1 NAME
route_validator.pl - Validate BGP/static routes on network devices

=head1 SYNOPSIS
route_validator.pl --host <device> --user <username> --pass <password> [--routes <file>] [--log <logfile>]

=head1 DESCRIPTION
Connects to network devices via SSH and validates that expected routes exist
in the routing table. Useful for BGP convergence verification, failover testing,
and route propagation audits. Reads expected routes from file or uses defaults.
Handles connection failures, timeouts, and authentication errors gracefully.

Prerequisites: Net::SSH::Expect module installed, SSH access to devices

=head1 OPTIONS
--host       Target device IP or hostname (required)
--user       SSH username (required)
--pass       SSH password (required)
--routes     File containing routes to validate (one per line), optional
--log        Optional log file for appending results

=head1 EXAMPLES
./route_validator.pl --host 10.0.1.1 --user admin --pass secret --routes routes.txt
./route_validator.pl --host router.example.com --user netadmin --pass pass123 --log audit.log

=cut

my ($host, $user, $pass, $routes_file, $log_file, $help);

GetOptions(
    'host=s'   => \$host,
    'user=s'   => \$user,
    'pass=s'   => \$pass,
    'routes=s' => \$routes_file,
    'log=s'    => \$log_file,
    'help'     => \$help,
) or die "Error in command line arguments\n";

if ($help || !$host || !$user || !$pass) {
    print "Usage: $0 --host <device> --user <username> --pass <password> ";
    print "[--routes <file>] [--log <logfile>]\n";
    exit 1;
}

my @routes_to_check = ('0.0.0.0/0');

if ($routes_file && -f $routes_file) {
    @routes_to_check = ();
    open my $fh, '<', $routes_file or die "Cannot open $routes_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^#/ || /^\s*$/;
        push @routes_to_check, $_;
    }
    close $fh;
}

my $log_handle;
if ($log_file) {
    open $log_handle, '>>', $log_file or die "Cannot open log file: $!\n";
}

sub log_msg {
    my ($msg) = @_;
    my $timestamp = scalar localtime;
    my $output = "[$timestamp] $msg";
    print "$output\n";
    print $log_handle "$output\n" if $log_handle;
}

log_msg("Starting route validation on $host");

my $ssh;
eval {
    $ssh = Net::SSH::Expect->new(
        host    => $host,
        user    => $user,
        password => $pass,
        timeout => 10,
        raw_pty => 1,
    );
};

if ($@) {
    log_msg("ERROR: Failed to create SSH connection: $@");
    exit 1;
}

eval {
    $ssh->login();
};

if ($@) {
    log_msg("ERROR: SSH login failed: $@");
    exit 1;
}

log_msg("Successfully connected to $host");

my $output = '';
eval {
    $ssh->send('terminal length 0');
    $ssh->waitfor('>', 3) or die "Timeout waiting for prompt\n";
    usleep(100000);
    
    $ssh->send('show ip route');
    $output = $ssh->waitfor('>', 5) or die "Timeout waiting for route output\n";
};

if ($@) {
    log_msg("ERROR: Failed to retrieve routes: $@");
    $ssh->close();
    exit 1;
}

$ssh->close();

my %route_status = ();
foreach my $route (@routes_to_check) {
    if ($output =~ /\Q$route\E/) {
        $route_status{$route} = 'FOUND';
        log_msg("Route found: $route");
    } else {
        $route_status{$route} = 'MISSING';
        log_msg("Route missing: $route");
    }
}

my $missing_count = grep { $_ eq 'MISSING' } values %route_status;
if ($missing_count > 0) {
    log_msg("WARNING: $missing_count route(s) missing from $host");
} else {
    log_msg("SUCCESS: All routes validated on $host");
}

close $log_handle if $log_handle;

exit ($missing_count > 0 ? 1 : 0);