#!/usr/bin/perl
# tacacs_connectivity_check.pl - Verify TACACS+ authentication server health
# Purpose: Validates TACACS+ server connectivity and response time on network devices
# Detects AAA infrastructure issues before they cause authentication outages
# Usage: ./tacacs_connectivity_check.pl <device> [<logfile>]
# Prerequisites: Expect module, SSH access, env vars NET_USER and NET_PASS
# Output: Diagnostic output to STDOUT + optional timestamped log file

use strict;
use warnings;
use Expect;
use Time::HiRes qw(time);

my ($device, $logfile) = @ARGV;
die "Usage: $0 <device> [<logfile>]\n" unless $device;

my $user = $ENV{NET_USER} || 'admin';
my $pass = $ENV{NET_PASS} || '';
my $timeout = 12;
my $ssh_timeout = 5;

sub log_output {
    my ($level, $msg) = @_;
    my $ts = scalar(localtime);
    my $output = "[$ts][$level] $msg";
    print "$output\n";
    if ($logfile) {
        open my $fh, '>>', $logfile or warn "Cannot write to $logfile: $!\n";
        print $fh "$output\n";
        close $fh;
    }
}

sub check_tacacs_server {
    my ($host) = @_;
    
    my $exp = Expect->new();
    $exp->log_stdout(0);
    my $result_status = 'OK';
    
    eval {
        log_output("INFO", "Initiating SSH connection to $host");
        
        $exp->spawn("ssh -o ConnectTimeout=$ssh_timeout -o StrictHostKeyChecking=no -l $user $host")
            or die "Cannot spawn SSH process: $!\n";
        
        $exp->expect($timeout,
            [ qr/password[:\s]*$/i, sub { $exp->send("$pass\n"); exp_continue; } ],
            [ qr/#\s*$|>\s*$/, sub { } ],
        ) or die "Authentication timeout or failed\n";
        
        log_output("INFO", "SSH authentication successful");
        
        # Query TACACS+ server status
        $exp->send("show tacacs\n");
        $exp->expect($timeout, qr/#\s*$|>\s*$/) or die "Command timeout on 'show tacacs'\n";
        my $tacacs_output = $exp->before();
        
        log_output("INFO", "TACACS+ Server Configuration:");
        foreach my $line (split /\n/, $tacacs_output) {
            next if $line =~ /^(show|#|>|$)/;
            log_output("INFO", "  $line") if $line =~ /\S/;
            $result_status = 'WARNING' if $line =~ /timeout|unreachable/i;
            $result_status = 'CRITICAL' if $line =~ /failed|down/i;
        }
        
        # Test TACACS+ connectivity if command exists
        $exp->send("test tacacs\n");
        $exp->expect($timeout, [ qr/#\s*$|>\s*$|Connection\s+(OK|Failed)/i, sub { } ]);
        my $test_output = $exp->before();
        
        if ($test_output =~ /success|ok|passed/i) {
            log_output("INFO", "TACACS+ server test: PASSED");
        } elsif ($test_output =~ /fail|error|unreachable/i) {
            log_output("CRIT", "TACACS+ server test: FAILED");
            $result_status = 'CRITICAL';
        } else {
            log_output("INFO", "TACACS+ server response received");
        }
        
        # Check for multiple TACACS+ servers (redundancy)
        $exp->send("show run | include tacacs\n");
        $exp->expect($timeout, qr/#\s*$|>\s*$/);
        my $config_output = $exp->before();
        
        my $server_count = 0;
        $server_count++ while $config_output =~ /tacacs-server\s+host/g;
        
        if ($server_count > 1) {
            log_output("INFO", "TACACS+ Redundancy: $server_count servers configured (GOOD)");
        } elsif ($server_count == 1) {
            log_output("WARN", "Single TACACS+ server - no redundancy");
            $result_status = 'WARNING' if $result_status eq 'OK';
        } else {
            log_output("CRIT", "No TACACS+ servers configured");
            $result_status = 'CRITICAL';
        }
        
        $exp->send("exit\n");
        $exp->soft_close();
        
        return $result_status;
        
    };
    
    if ($@) {
        log_output("CRIT", "Connection error: $@");
        return 'ERROR';
    }
}

log_output("INFO", "=== TACACS+ Connectivity Check ===" );
log_output("INFO", "Target device: $device");
log_output("INFO", "Starting verification...");
log_output("INFO", "-" x 50);

my $status = check_tacacs_server($device);

log_output("INFO", "-" x 50);
log_output("INFO", "Final Status: $status");
log_output("INFO", "=== Check Complete ===");

exit($status eq 'OK' ? 0 : ($status eq 'WARNING' ? 1 : 2));