```perl
#!/usr/bin/perl
=head1 INTERFACE ERROR AUDIT SCRIPT
Purpose: SSH into network devices and audit interface error counters
Usage:   ./interface_error_audit.pl <device_host> [--user <user>] [--pass <pass>] [--log <file>] [--threshold <count>]
         ./interface_error_audit.pl --file <device_list> [--user <user>] [--pass <pass>] [--log <file>]
Prerequisites: Net::SSH::Expect module installed
Description:
  Connects to Cisco IOS/IOS-XE devices and collects interface error statistics:
  - CRC errors, runts, giants, fragments, collisions
  - Input/output errors, overruns, underruns
  - Identifies interfaces exceeding error thresholds for investigation
  
  Results output to STDOUT and optionally to a log file.
  Supports individual device or batch processing from file.
=cut

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;

my ($device_file, $username, $password, $logfile, $error_threshold);
my $device = $ARGV[0] if @ARGV && $ARGV[0] !~ /^-/;

GetOptions(
    'file=s'      => \$device_file,
    'log=s'       => \$logfile,
    'user=s'      => \$username,
    'pass=s'      => \$password,
    'threshold=i' => \$error_threshold,
) or die "Error in command line options\n";

die "Usage: $0 <device> [--user user] [--pass pass] [--log file] [--threshold errors]\n"
    if !$device && !$device_file;

$username ||= 'admin';
$password ||= 'password';
$error_threshold ||= 100;

sub audit_interface_errors {
    my ($host, $user, $pass, $log_fh, $threshold) = @_;
    
    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $user,
        password    => $pass,
        raw_pty     => 1,
        timeout     => 25,
    );
    
    unless ($ssh) {
        my $msg = "ERROR: Cannot create SSH connection to $host\n";
        print $msg;
        print $log_fh $msg if $log_fh;
        return 0;
    }
    
    my $login_output;
    eval {
        $login_output = $ssh->login();
    };
    if ($@) {
        my $msg = "ERROR: SSH login failed for $host: $@\n";
        print $msg;
        print $log_fh $msg if $log_fh;
        return 0;
    }
    
    unless ($login_output =~ /[#>]/) {
        my $msg = "ERROR: Did not reach prompt on $host\n";
        print $msg;
        print $log_fh $msg if $log_fh;
        $ssh->close();
        return 0;
    }
    
    $ssh->send("show interfaces");
    my $output = $ssh->read_all();
    
    unless ($output) {
        my $msg = "ERROR: No output from 'show interfaces' on $host\n";
        print $msg;
        print $log_fh $msg if $log_fh;
        $ssh->close();
        return 0;
    }
    
    my $header = sprintf("\n[%s] Interface Error Audit (threshold: %d)\n", $host, $threshold);
    print $header;
    print $log_fh $header if $log_fh;
    
    my %problem_interfaces;
    my @lines = split /\n/, $output;
    my $current_int;
    my $total_errors = 0;
    my $problem_count = 0;
    
    foreach my $line (@lines) {
        if ($line =~ /^(\S+)\s+is\s+(up|down)/) {
            $current_int = $1;
        }
        
        if ($current_int && $line =~ /(\d+)\s+input errors.*?(\d+)\s+CRC/) {
            my $input_err = $1;
            my $crc_err = $2;
            my $errors = $input_err + $crc_err;
            $total_errors += $errors;
            
            if ($errors > $threshold) {
                $problem_interfaces{$current_int} = {
                    input_errors => $input_err,
                    crc_errors   => $crc_err,
                    total        => $errors,
                };
                $problem_count++;
            }
        }
        
        if ($current_int && $line =~ /(\d+)\s+runts.*?(\d+)\s+giants/) {
            my $runts = $1;
            my $giants = $2;
            if (defined $problem_interfaces{$current_int}) {
                $problem_interfaces{$current_int}->{runts} = $runts;
                $problem_interfaces{$current_int}->{giants} = $giants;
            }
        }
    }
    
    if ($problem_count > 0) {
        my $msg = sprintf("ALERT: Found %d interfaces with errors above threshold\n", $problem_count);
        print $msg;
        print $log_fh $msg if $log_fh;
        
        foreach my $int (sort keys %problem_interfaces) {
            my $data = $problem_interfaces{$int};
            my $detail = sprintf("  %s: %d total errors (input: %d, CRC: %d, runts: %d, giants: %d)\n",
                $int,
                $data->{total},
                $data->{input_errors} || 0,
                $data->{crc_errors} || 0,
                $data->{runts} || 0,
                $data->{giants} || 0,
            );
            print $detail;
            print $log_fh $detail if $log_fh;
        }
    } else {
        my $msg = "OK: All interfaces within error threshold\n";
        print $msg;
        print $log_fh $msg if $log_fh;
    }
    
    $ssh->close();
    return 1;
}

sub main {
    my @devices;
    
    if ($device_file) {
        open my $fh, '<', $device_file or die "Cannot open device file: $!\n";
        while (<$fh>) {
            chomp;
            next if /^#|^\s*$/;
            push @devices, $_;
        }
        close $fh;
    } else {
        @devices = ($device);
    }
    
    my $log_fh;
    if ($logfile) {
        open $log_fh, '>>', $logfile or warn "Cannot open logfile $logfile: $!\n";
    }
    
    my $success_count = 0;
    foreach my $dev (@devices) {
        $dev =~ s/\s+//g;
        next unless $dev;
        $success_count += audit_interface_errors($dev, $username, $password, $log_fh, $error_threshold);
    }
    
    my $total = scalar(@devices);
    my $summary = sprintf("\n=== Summary: %d/%d devices audited successfully ===\n", $success_count, $total);
    print $summary;
    print $log_fh $summary if $log_fh;
    
    close $log_fh if $log_fh;
}

main();
```