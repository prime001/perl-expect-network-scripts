```perl
#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::localtime;

# stp_audit.pl - Spanning Tree Protocol topology and configuration audit
# Audits STP status, bridge priorities, port roles, and topology stability
# Usage: perl stp_audit.pl --host 192.168.1.1 --user admin --pass pass123
#        perl stp_audit.pl --file devices.txt --user admin --pass pass123 --logdir ./logs
# Prerequisites: Net::SSH::Expect, SSH access to Cisco switches

my ($host, $file, $user, $pass, $logfile, $logdir, $timeout, $help);
$timeout = 30;

GetOptions(
    'host=s'    => \$host,
    'file=s'    => \$file,
    'user=s'    => \$user,
    'pass=s'    => \$pass,
    'logfile=s' => \$logfile,
    'logdir=s'  => \$logdir,
    'timeout=i' => \$timeout,
    'help'      => \$help,
) or die "Invalid command line arguments\n";

die "Error: Specify --host or --file\n" unless ($host || $file);
die "Error: --user and --pass required\n" unless ($user && $pass);

sub log_msg {
    my ($msg, $logfh) = @_;
    print "$msg\n";
    print $logfh "$msg\n" if defined $logfh;
}

sub ssh_connect {
    my ($host, $user, $pass, $timeout) = @_;
    my $expect;
    
    eval {
        $expect = Net::SSH::Expect->new(
            host     => $host,
            user     => $user,
            password => $pass,
            timeout  => $timeout,
            raw_pty  => 1,
        );
        $expect->connect() or die "SSH connection failed\n";
        $expect->exec("terminal length 0");
    };
    
    if ($@) {
        warn "Connection to $host failed: $@";
        return undef;
    }
    
    return $expect;
}

sub audit_stp {
    my ($host, $expect, $logfh) = @_;
    
    log_msg("\n" . "="x60, $logfh);
    log_msg("STP Audit: $host [" . scalar(localtime()) . "]", $logfh);
    log_msg("="x60, $logfh);
    
    my %commands = (
        'STP Summary' => 'show spanning-tree summary',
        'Root Bridge' => 'show spanning-tree root',
        'Bridge Priorities' => 'show spanning-tree vlan 1 | include Bridge',
        'Port States' => 'show spanning-tree interface brief',
        'BPDU Guard' => 'show spanning-tree portfast bpdu-guard',
        'Topology Changes' => 'show spanning-tree | include Topology',
    );
    
    foreach my $label (sort keys %commands) {
        log_msg("\n--- $label ---", $logfh);
        
        my @output;
        eval {
            @output = $expect->exec($commands{$label});
        };
        
        if ($@) {
            log_msg("ERROR executing command: $@", $logfh);
            next;
        }
        
        my $count = 0;
        foreach my $line (@output) {
            chomp($line);
            next if $line =~ /^\s*$/ || $line =~ /^$/;
            log_msg($line, $logfh);
            $count++;
            last if $count > 25;
        }
    }
    
    log_msg("\n" . "="x60 . "\n", $logfh);
}

my @devices = ();
if ($host) {
    @devices = ($host);
} elsif ($file) {
    open(my $fh, '<', $file) or die "Cannot open $file: $!\n";
    while (my $line = <$fh>) {
        chomp($line);
        next if $line =~ /^\s*#/ || $line =~ /^\s*$/;
        push @devices, $line;
    }
    close($fh);
}

my $success_count = 0;
foreach my $device (@devices) {
    my $logfh;
    
    if ($logdir) {
        mkdir($logdir) unless -d $logdir;
        my $path = "$logdir/${device}_stp_audit.log";
        if (open($logfh, '>', $path)) {
            print "[LOG] Writing to $path\n";
        } else {
            warn "Cannot write to $path: $!\n";
        }
    } elsif ($logfile) {
        if (!open($logfh, '>', $logfile)) {
            warn "Cannot write to $logfile: $!\n";
        }
    }
    
    my $ssh = ssh_connect($device, $user, $pass, $timeout);
    if ($ssh) {
        eval {
            audit_stp($device, $ssh, $logfh);
            $success_count++;
        };
        
        if ($@) {
            log_msg("ERROR during audit: $@", $logfh);
        }
        
        eval { $ssh->close(); };
    } else {
        log_msg("FAILED: Cannot connect to $device", $logfh);
    }
    
    close($logfh) if defined $logfh && fileno($logfh);
}

print "\nAudit completed: $success_count/" . scalar(@devices) . " successful\n";
```