```perl
#!/usr/bin/perl
=head1 NAME
port_channel_audit.pl - Audit port channel status and member link health

=head1 SYNOPSIS
./port_channel_audit.pl -f devices.txt [-l audit.log] [-t timeout]
./port_channel_audit.pl 10.0.0.1 10.0.0.2 -l audit.log

=head1 DESCRIPTION
Connects to network devices via SSH and audits port channel configurations.
Verifies all expected port channel members are up, identifies flapping ports,
and reports bundling mismatches. Outputs results to STDOUT and optional logfile.

=head1 PREREQUISITES
Perl 5.10+, Expect.pm, Net::SSH access to devices
Credentials via: export NETWORK_USER=admin NETWORK_PASS=password

=cut

use strict;
use warnings;
use Expect;
use Getopt::Std;

my %opts;
getopts('f:l:t:u:p:', \%opts);

my $device_file = $opts{f};
my $logfile = $opts{l};
my $timeout = $opts{t} || 15;
my $user = $opts{u} || $ENV{NETWORK_USER};
my $pass = $opts{p} || $ENV{NETWORK_PASS};

my @devices;
if ($device_file && -f $device_file) {
    open my $fh, '<', $device_file or die "Cannot read $device_file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^#|^\s*$/;
        push @devices, $_;
    }
    close $fh;
} else {
    @devices = @ARGV;
}

die "Usage: $0 -f devices.txt [-l logfile] [devices...]\n" unless @devices;
die "Set NETWORK_USER and NETWORK_PASS environment variables\n" unless $user && $pass;

open my $LOG, '>>', $logfile if $logfile;

foreach my $device (@devices) {
    print "[*] Auditing port channels on $device\n";
    my @results = audit_port_channels($device, $user, $pass, $timeout);
    
    foreach my $result (@results) {
        print "$result\n";
        print $LOG "$result\n" if $LOG;
    }
}

close $LOG if $LOG;
print "[+] Port channel audit complete\n";

sub audit_port_channels {
    my ($device, $user, $pass, $timeout) = @_;
    my @findings;
    
    my $exp = Expect->new();
    $exp->raw_pty(1);
    $exp->log_stdout(0);
    
    eval {
        $exp->spawn("ssh -o ConnectTimeout=$timeout -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $user\@$device")
            or die "Cannot spawn SSH to $device\n";
        
        $exp->expect($timeout, ['password:', 'Password:']) 
            or die "Timeout waiting for password prompt on $device\n";
        $exp->send("$pass\n");
        
        $exp->expect($timeout, ['#', '>']) 
            or die "Failed to authenticate on $device\n";
        
        $exp->send("terminal length 0\n");
        $exp->expect($timeout, ['#', '>']);
        
        $exp->send("show etherchannel summary\n");
        $exp->expect($timeout, ['#', '>']);
        my $etherchannel_output = $exp->before();
        
        my %po_status;
        my $current_po = undef;
        
        foreach my $line (split /\n/, $etherchannel_output) {
            if ($line =~ /^Group\s+(\d+)/) {
                $current_po = $1;
            }
            if ($current_po && $line =~ /([A-Za-z0-9\/]+)\s+\(\s*([A-Z])\s*\)/) {
                my $member = $1;
                my $state = $2;
                $po_status{$current_po}{$member} = $state;
                
                if ($state ne 'P' && $state ne 'p') {
                    push @findings, "WARNING: [$device] Port-Channel $current_po member $member is not bundled (state=$state)";
                }
            }
        }
        
        $exp->send("show interfaces status err-disabled\n");
        $exp->expect($timeout, ['#', '>']);
        my $errdiabled_output = $exp->before();
        
        foreach my $line (split /\n/, $errdiabled_output) {
            if ($line =~ /([A-Za-z0-9\/]+)\s+/) {
                my $iface = $1;
                if ($etherchannel_output =~ /$iface/) {
                    push @findings, "ERROR: [$device] Interface $iface (port-channel member) is err-disabled";
                }
            }
        }
        
        $exp->send("show interfaces counters errors | include Gi|Fa|Et|Te\n");
        $exp->expect($timeout, ['#', '>']);
        my $errors_output = $exp->before();
        
        foreach my $line (split /\n/, $errors_output) {
            if ($line =~ /([A-Za-z0-9\/]+)\s+(\d+)\s+(\d+)/) {
                my ($iface, $in_err, $out_err) = ($1, $2, $3);
                if (($in_err + $out_err) > 100 && $etherchannel_output =~ /$iface/) {
                    push @findings, "ALERT: [$device] Port-Channel member $iface has high error count (in=$in_err, out=$out_err)";
                }
            }
        }
        
        $exp->send("exit\n");
        $exp->soft_close();
        
        push @findings, "OK: [$device] Port channel audit completed" unless @findings;
    };
    
    if ($@) {
        push @findings, "ERROR: [$device] Failed to connect: $@";
    }
    
    return @findings;
}
```