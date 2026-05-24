#!/usr/bin/perl
# Route Table Analyzer - Analyze routing table entries and identify anomalies
# Purpose: SSH into network devices, collect routing table statistics, detect anomalies
# Usage: ./route_analyzer.pl --device 192.168.1.1 --username admin --password secret
#        ./route_analyzer.pl --file devices.txt --username admin --password secret [--logfile results.log]
# Prerequisites: Expect module, SSH access with sufficient privileges, password/key auth

use strict;
use warnings;
use Expect;
use Getopt::Long;
use Time::gmtime;

my ($device, $file, $username, $password, $logfile, $timeout);
GetOptions(
    'device=s'   => \$device,
    'file=s'     => \$file,
    'username=s' => \$username,
    'password=s' => \$password,
    'logfile=s'  => \$logfile,
    'timeout=i'  => \$timeout,
) or die "Error in command line arguments\n";

die "Specify --device or --file\n" unless ($device || $file);
die "Username and password required\n" unless ($username && $password);

$timeout ||= 10;
my @devices = $device ? ($device) : read_device_file($file);

print "=" x 80 . "\nRoute Table Analysis Report\n" . "=" x 80 . "\n";

foreach my $dev (@devices) {
    analyze_routes($dev, $username, $password, $timeout, $logfile);
}

sub analyze_routes {
    my ($dev, $user, $pass, $to, $log) = @_;
    my $exp = Expect->new();
    $exp->raw_pty(1);
    $exp->log_stdout(0);
    
    eval {
        $exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -l $user $dev");
    };
    if ($@) {
        log_output("[$dev] ERROR: Connection failed - $@", $log);
        return;
    }
    
    unless ($exp->expect($to, ['assword:', 'timeout'])) {
        log_output("[$dev] ERROR: Timeout waiting for password prompt", $log);
        $exp->hard_close();
        return;
    }
    
    $exp->send("$pass\n");
    unless ($exp->expect($to, ['[#>]', 'denied', 'timeout'])) {
        log_output("[$dev] ERROR: Authentication timeout", $log);
        $exp->hard_close();
        return;
    }
    
    if ($exp->before() =~ /denied|incorrect/i) {
        log_output("[$dev] ERROR: Authentication failed", $log);
        $exp->hard_close();
        return;
    }
    
    $exp->send("show ip route\n");
    $exp->expect($to, '[#>]');
    my $route_output = $exp->before();
    
    $exp->send("exit\n");
    $exp->expect($to, 'timeout');
    $exp->hard_close();
    
    my %stats = parse_routes($route_output);
    generate_report($dev, \%stats, $log);
}

sub parse_routes {
    my ($output) = @_;
    my %stats = (total => 0, connected => 0, static => 0, ospf => 0, bgp => 0, rip => 0, eigrp => 0);
    
    foreach my $line (split /\n/, $output) {
        next if $line =~ /^\s*$/;
        $stats{total}++ if $line =~ /^\s*[OCS\*]/;
        $stats{connected}++ if $line =~ /C\s+\*?.*directly connected/i;
        $stats{static}++ if $line =~ /^\s*S/;
        $stats{ospf}++ if $line =~ /^\s*O/;
        $stats{bgp}++ if $line =~ /^\s*B/;
        $stats{rip}++ if $line =~ /^\s*R\s/;
        $stats{eigrp}++ if $line =~ /^\s*D\s/;
    }
    
    return %stats;
}

sub generate_report {
    my ($dev, $stats, $log) = @_;
    
    my $output = "\n[Device: $dev]\n" . ("-" x 70) . "\n";
    $output .= sprintf("Total Routes: %-4d | Connected: %-3d | Static: %-3d | OSPF: %-3d | BGP: %-3d | RIP: %-3d | EIGRP: %-3d\n",
        $stats->{total}, $stats->{connected}, $stats->{static}, $stats->{ospf}, $stats->{bgp}, $stats->{rip}, $stats->{eigrp});
    
    if ($stats->{total} == 0) {
        $output .= "WARNING: No routes detected - check device connectivity\n";
    }
    if ($stats->{total} > 500) {
        $output .= "ALERT: Excessive route count detected (>500 routes)\n";
    }
    if (($stats->{ospf} + $stats->{bgp}) == 0 && $stats->{total} > 2) {
        $output .= "ALERT: No dynamic routing protocols detected\n";
    }
    if ($stats->{static} > ($stats->{total} * 0.5) && $stats->{total} > 5) {
        $output .= "ALERT: Static routes exceed 50% of total - verify routing redundancy\n";
    }
    
    print $output;
    log_output($output, $log);
}

sub read_device_file {
    my ($file) = @_;
    die "File not found: $file\n" unless -f $file;
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    my @devices;
    while (<$fh>) {
        chomp;
        next if /^#/ || /^\s*$/;
        push @devices, $_;
    }
    close $fh;
    die "No devices found in $file\n" unless @devices;
    return @devices;
}

sub log_output {
    my ($message, $logfile) = @_;
    return unless $logfile;
    open my $fh, '>>', $logfile or do {
        warn "WARNING: Cannot write to $logfile: $!\n";
        return;
    };
    print $fh $message;
    close $fh;
}