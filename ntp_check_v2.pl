```perl
#!/usr/bin/perl
=head1 stp_audit.pl - Spanning Tree Status Auditor

=head1 SYNOPSIS
  stp_audit.pl --host <device_ip> [--user <name>] [--pass <pw>] [--log <file>]
  stp_audit.pl --file <devices.txt> [options]

=head1 DESCRIPTION
Audits Spanning Tree Protocol (STP) configuration and topology on Cisco devices
via SSH. Collects root bridge info, topology changes, and port states. Useful
for validating STP stability and detecting topology flaps or suboptimal root
bridge placement.

=head1 PREREQUISITES
  - Perl modules: Expect
  - SSH access to network devices with enable mode
  - STP/RSTP enabled on device VLAN(s)
  - Valid SSH credentials

=head1 OPTIONS
  --host <ip>       Device IP or hostname to audit
  --file <file>     File with device list (one per line)
  --user <name>     SSH username (prompts if not provided)
  --pass <password> SSH password (prompts if not provided)
  --log <file>      Append results to log file (optional)
  --timeout <sec>   SSH command timeout (default: 30 seconds)

=cut

use strict;
use warnings;
use Expect;
use Getopt::Long;
use Time::HiRes qw(time);

my %opts = (timeout => 30);
GetOptions(
    'host=s'    => \$opts{host},
    'file=s'    => \$opts{file},
    'user=s'    => \$opts{user},
    'pass=s'    => \$opts{pass},
    'log=s'     => \$opts{log},
    'timeout=i' => \$opts{timeout},
) or die "Option parsing failed\n";

die "Specify --host or --file\n" unless $opts{host} || $opts{file};

my @devices;
if ($opts{file}) {
    open my $fh, '<', $opts{file} or die "Cannot read $opts{file}: $!\n";
    @devices = map { chomp; $_ } <$fh>;
    close $fh;
} else {
    @devices = ($opts{host});
}

my $logfh;
open $logfh, '>>', $opts{log} if $opts{log};

sub log_msg {
    my $msg = shift;
    print "$msg\n";
    print $logfh "$msg\n" if $logfh;
}

sub audit_stp_device {
    my $device = shift;
    my $start = time();
    
    log_msg("\n" . "="x65);
    log_msg("STP Audit: $device @ " . scalar(localtime));
    
    my $exp = Expect->new();
    $exp->log_stdout(0);
    $exp->debug(0);
    
    eval {
        $exp->spawn("ssh", "-o", "StrictHostKeyChecking=no",
                   "-o", "ConnectTimeout=10",
                   "$opts{user}\@$device")
            or die "SSH spawn failed: $!\n";
        
        $exp->expect($opts{timeout},
            ['password:', sub { $_[0]->send("$opts{pass}\r"); exp_continue; }],
            [qr/[#>]/, sub { }]
        ) or die "SSH auth timeout\n";
        
        $exp->send("enable\r");
        $exp->expect(2,
            ['password:', sub { $_[0]->send("$opts{pass}\r"); exp_continue; }],
            [timeout => sub { }]
        );
        
        log_msg("\n[ROOT BRIDGE INFO]");
        $exp->send("show spanning-tree root\r");
        $exp->expect($opts{timeout}, qr/[#>]/);
        for (split /\n/, $exp->before) {
            log_msg($_) if /Root ID|Bridge ID|Root Port|Cost/i && !/^show/i;
        }
        
        log_msg("\n[VLAN TOPOLOGY SUMMARY]");
        $exp->send("show spanning-tree vlan 1\r");
        $exp->expect($opts{timeout}, qr/[#>]/);
        for (split /\n/, $exp->before) {
            log_msg($_) if /VLAN|Root|Bridge|Designated|Priority/i && !/^show/i;
        }
        
        log_msg("\n[TOPOLOGY CHANGE COUNTER]");
        $exp->send("show spanning-tree summary\r");
        $exp->expect($opts{timeout}, qr/[#>]/);
        for (split /\n/, $exp->before) {
            log_msg($_) if /Topology Changes|Forwarding|Blocking|Disabled/i;
        }
        
        log_msg("\n[INTERFACE STATES]");
        $exp->send("show spanning-tree interface brief\r");
        $exp->expect($opts{timeout}, qr/[#>]/);
        my $port_count = 0;
        for (split /\n/, $exp->before) {
            if (/\s+(Gi|Fa|Et|Po|Te)\S+\s+\d+\s+(forw|block|disabl|root|desg)/i) {
                log_msg($_);
                $port_count++;
            }
        }
        log_msg("Ports analyzed: $port_count");
        
        $exp->send("exit\r");
        $exp->soft_close();
        
        my $elapsed = sprintf("%.2f", time() - $start);
        log_msg("\nStatus: SUCCESS (${elapsed}s)");
        
    } or do {
        log_msg("Status: FAILED - $@");
    };
    
    $exp->hard_close() if $exp;
}

unless ($opts{user}) {
    print "SSH Username: ";
    chomp($opts{user} = <STDIN>);
}

unless ($opts{pass}) {
    print "SSH Password: ";
    system("stty -echo");
    chomp($opts{pass} = <STDIN>);
    system("stty echo");
    print "\n";
}

log_msg("STP Spanning Tree Auditor");
log_msg("Start: " . scalar(localtime()));
log_msg("Device count: " . scalar(@devices));

foreach my $dev (@devices) {
    next unless $dev;
    audit_stp_device($dev);
}

log_msg("\n" . "="x65);
log_msg("All audits completed: " . scalar(localtime()));
close $logfh if $logfh;
```