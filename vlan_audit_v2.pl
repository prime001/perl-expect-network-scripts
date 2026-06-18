The prompt asks for script content only — no file to write here. Here is the script:

```
#!/usr/bin/perl
#
# vlan_svi_audit.pl - VLAN SVI Layer 3 Health Auditor
#
# Purpose:
#   Audits Layer 3 SVI health for all active VLANs on Cisco IOS/IOS-XE switches.
#   Reports VLANs missing SVIs, SVIs in down state, SVIs lacking IP addresses,
#   and provides a summary of L2-only vs routed VLANs. Useful for detecting
#   silent L3 failures invisible to basic VLAN table audits.
#
# Usage:
#   ./vlan_svi_audit.pl -h <host> [-u user] [-p pass] [-l logfile]
#   ./vlan_svi_audit.pl -f devices.txt [-u user] [-p pass] [-l logfile]
#   NET_USER=admin NET_PASS=secret ./vlan_svi_audit.pl -f core-switches.txt
#
# Prerequisites:
#   cpan install Net::SSH::Expect
#   SSH access with 'show' privilege; device prompt must match hostname#

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $user, $password, $device_file, $logfile, $help);
$user     = $ENV{NET_USER} // 'admin';
$password = $ENV{NET_PASS} // '';

GetOptions(
    'h|host=s'     => \$host,
    'u|user=s'     => \$user,
    'p|password=s' => \$password,
    'f|file=s'     => \$device_file,
    'l|log=s'      => \$logfile,
    'help'         => \$help,
) or die "Option error. Use --help for usage.\n";

if ($help || (!$host && !$device_file)) {
    print "Usage: $0 -h <host> | -f <file> [-u user] [-p pass] [-l logfile]\n";
    exit 0;
}

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*[#;]/ || /^\s*$/; push @devices, $_; }
    close $fh;
}
die "No devices specified.\n" unless @devices;

my $log_fh;
if ($logfile) {
    open($log_fh, '>', $logfile) or die "Cannot open $logfile: $!\n";
}

sub out {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime);
out("=" x 60 . "\nVLAN SVI Health Audit  -  $ts\n" . "=" x 60 . "\n\n");

for my $device (@devices) {
    out("Device: $device\n" . "-" x 40 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host       => $device,
        user       => $user,
        password   => $password,
        raw_pty    => 1,
        timeout    => 15,
        ssh_option => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
    );

    eval {
        my $banner = $ssh->login();
        die "Unexpected prompt (auth failed?)\n" unless $banner =~ /[>#]/;
    };
    if ($@) {
        out("  ERROR: $@\n\n");
        next;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('\#', 5);

    $ssh->send('show vlan brief');
    my $vlan_out = $ssh->waitfor('\#', 15) // '';

    $ssh->send('show ip interface brief | include Vlan');
    my $ip_out = $ssh->waitfor('\#', 15) // '';

    eval { $ssh->close() };

    # Parse active VLANs (id + name, status=active)
    my %vlans;
    for (split /\n/, $vlan_out) {
        $vlans{$1} = $2 if /^\s*(\d+)\s+(\S+)\s+active/i;
    }

    # Parse SVI entries from ip interface brief
    my (%svi_ip, %svi_state);
    for (split /\n/, $ip_out) {
        if (/Vlan(\d+)\s+(\S+)\s+(\S+)\s+(\S+)/i) {
            $svi_ip{$1}    = $2;
            $svi_state{$1} = "$3/$4";
        }
    }

    my (@down, @no_ip, @no_svi, @ok);
    for my $vid (sort { $a <=> $b } keys %vlans) {
        next if $vid == 1;
        if (!exists $svi_state{$vid}) {
            push @no_svi, $vid;
        } elsif ($svi_state{$vid} !~ m{up/up}i) {
            push @down, { vid => $vid, st => $svi_state{$vid},
                          ip  => ($svi_ip{$vid} // 'unassigned') };
        } elsif (($svi_ip{$vid} // '') =~ /unassigned|^\s*$/) {
            push @no_ip, $vid;
        } else {
            push @ok, "$vid ($svi_ip{$vid})";
        }
    }

    my $total = scalar keys %vlans;
    out(sprintf("  VLANs active: %-4d  SVI OK: %-4d  Down: %-4d  No IP: %-4d  L2-only: %d\n\n",
        $total, scalar @ok, scalar @down, scalar @no_ip, scalar @no_svi));

    if (@down) {
        out("  [WARN] SVIs not up/up:\n");
        out(sprintf("    VLAN %-5d  %-12s  %s\n",
            $_->{vid}, $_->{st}, $_->{ip})) for @down;
        out("\n");
    }
    if (@no_ip) {
        out("  [WARN] SVIs up but no IP assigned: " . join(', ', @no_ip) . "\n\n");
    }
    if (@no_svi) {
        out("  [INFO] L2-only VLANs (no SVI): " . join(', ', @no_svi) . "\n\n");
    }
    out("  [OK] Routed SVIs: " . join(', ', @ok) . "\n\n") if @ok;
}

out("Audit complete.\n");
close $log_fh if $log_fh;
```

This is `vlan_svi_audit.pl` — it audits Layer 3 SVI health rather than the VLAN table itself, making it complementary to the existing `vlan_audit.pl`/`vlan_audit_v2.pl`. Key differentiators: correlates `show vlan brief` against `show ip interface brief` to classify each active VLAN as routed-healthy, SVI-down, SVI-missing-IP, or L2-only. Accepts a device list file, reads credentials from env vars, and supports optional log output. ~115 lines.