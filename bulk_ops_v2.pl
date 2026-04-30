#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Carp;

=head1 NAME
007_interface_stats_monitor.pl - Interface statistics and health monitoring

=head1 SYNOPSIS
    perl 007_interface_stats_monitor.pl --host 192.168.1.1 --user admin --pass password [--logfile report.txt]
    perl 007_interface_stats_monitor.pl --file devices.txt --user admin --pass password [--logfile report.txt]

=head1 DESCRIPTION
Monitors interface health across Cisco IOS devices by collecting statistics on errors, 
discards, and operational status. Identifies problematic interfaces with high error rates 
or unexpected operational states. Useful for preventive maintenance and troubleshooting.

=head1 PREREQUISITES
- Net::SSH::Expect installed (cpan -i Net::SSH::Expect)
- SSH access enabled on devices
- Read-only credentials sufficient for show commands
- Cisco IOS 12.0 or later (or compatible firmware)

=head1 PARAMETERS
    --host/-h       Device IP or hostname (or use --file for bulk)
    --file/-f       File with device IPs/hostnames, one per line
    --user/-u       SSH username
    --pass/-p       SSH password
    --timeout/-t    SSH timeout in seconds (default: 20)
    --logfile/-l    Append results to log file (optional)
    --verbose/-v    Enable verbose error output

=head1 EXAMPLE
    perl 007_interface_stats_monitor.pl --file production_devices.txt \
        --user readuser --pass readpass --logfile interface_health.log

=cut

my ($host, $file, $user, $pass, $timeout, $logfile, $verbose);
GetOptions(
    'host|h=s'      => \$host,
    'file|f=s'      => \$file,
    'user|u=s'      => \$user,
    'pass|p=s'      => \$pass,
    'timeout|t=i'   => \$timeout,
    'logfile|l=s'   => \$logfile,
    'verbose|v'     => \$verbose,
) or die "Usage: $0 --host <ip> --user <user> --pass <pass> [options]\n";

die "Error: Specify --host or --file\n" unless ($host || $file);
die "Error: --user and --pass are required\n" unless ($user && $pass);

$timeout ||= 20;

my @devices = $host ? ($host) : read_device_file($file);
die "Error: No devices found\n" unless @devices;

my $full_report;
foreach my $device (@devices) {
    $full_report .= monitor_interfaces($device, $user, $pass, $timeout);
}

print $full_report;
write_logfile($logfile, $full_report) if $logfile;

exit 0;

sub monitor_interfaces {
    my ($device, $user, $pass, $timeout) = @_;
    my $report = "=" x 70 . "\n";
    $report .= "DEVICE: $device\n";
    $report .= "=" x 70 . "\n";
    
    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $device,
            user     => $user,
            password => $pass,
            timeout  => $timeout,
            raw_pty  => 1,
        );
        $ssh->login() or croak "SSH login failed";
    };
    
    if ($@) {
        $report .= "[FAILED] Connection error: $@\n\n";
        warn "[ERROR] $device: $@\n" if $verbose;
        return $report;
    }
    
    eval {
        # Disable paging to ensure complete output
        $ssh->send("terminal length 0");
        $ssh->waitfor('>', $timeout);
        
        # Retrieve interface statistics
        $ssh->send("show interfaces");
        my $output = $ssh->waitfor('>', $timeout);
        
        my %interfaces;
        my $current_iface = '';
        
        # Parse interface output
        foreach my $line (split /\n/, $output) {
            if ($line =~ /^(\S+)\s+is\s+(up|down),\s+line\s+protocol\s+is\s+(up|down)/i) {
                $current_iface = $1;
                $interfaces{$current_iface} = {
                    admin_status => lc($2),
                    protocol_status => lc($3),
                    errors => 0,
                    discards => 0,
                };
            }
            
            if ($current_iface) {
                if ($line =~ /(\d+)\s+input errors/) {
                    $interfaces{$current_iface}{errors} += $1;
                }
                if ($line =~ /(\d+)\s+output errors/) {
                    $interfaces{$current_iface}{errors} += $1;
                }
                if ($line =~ /(\d+)\s+(dropped|discarded)/) {
                    $interfaces{$current_iface}{discards} += $1;
                }
            }
        }
        
        # Generate report
        my ($up_count, $down_count, $error_count) = (0, 0, 0);
        
        foreach my $iface (sort keys %interfaces) {
            my $data = $interfaces{$iface};
            
            if ($data->{admin_status} eq 'down' || $data->{protocol_status} eq 'down') {
                $down_count++;
                $report .= "[DOWN] $iface (admin: $data->{admin_status}, "
                        .  "protocol: $data->{protocol_status})\n";
            } else {
                $up_count++;
            }
            
            if ($data->{errors} > 0 || $data->{discards} > 0) {
                $error_count++;
                $report .= "  [ISSUES] $iface: $data->{errors} errors, "
                        .  "$data->{discards} discards\n";
            }
        }
        
        $report .= "\nSUMMARY:\n";
        $report .= "  Total Interfaces: " . (scalar keys %interfaces) . "\n";
        $report .= "  Up: $up_count | Down: $down_count | With Errors: $error_count\n\n";
        
        $ssh->send("exit");
        $ssh->close();
        
    };
    
    if ($@) {
        $report .= "[ERROR] Command execution failed: $@\n\n";
        warn "[ERROR] $device execution: $@\n" if $verbose;
        $ssh->close() if $ssh;
    }
    
    return $report;
}

sub read_device_file {
    my ($file) = @_;
    open my $fh, '<', $file or croak "Cannot open $file: $!";
    my @devices = map { chomp; $_ } grep { /\S/ } <$fh>;
    close $fh;
    return @devices;
}

sub write_logfile {
    my ($file, $content) = @_;
    open my $fh, '>>', $file or croak "Cannot write to $file: $!";
    printf $fh "[%s] Interface Statistics Report\n", scalar localtime;
    print $fh $content;
    print $fh "\n";
    close $fh;
}

__END__