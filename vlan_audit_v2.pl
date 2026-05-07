The user asked for raw script content output only. Here it is:

#!/usr/bin/perl
# trunk_vlan_audit.pl - Cisco IOS trunk port pruning and VTP audit
#
# PURPOSE:
#   Audits trunk interfaces on Cisco IOS/IOS-XE switches to identify
#   over-permissive VLAN configurations (trunks allowing all 4094 VLANs),
#   excessive VLAN leakage (many allowed but few active), and VTP status
#   anomalies. Complements vlan_audit.pl which inventories the VLAN database;
#   this script focuses on what traverses trunk links and flags hygiene issues.
#
# USAGE:
#   Single device:  perl trunk_vlan_audit.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    perl trunk_vlan_audit.pl -f devices.txt -u admin -p secret
#   With log:       perl trunk_vlan_audit.pl -h 192.168.1.1 -u admin -p secret -l audit.log
#   With enable:    perl trunk_vlan_audit.pl -h 192.168.1.1 -u admin -p secret -e enablepass
#
# DEVICE FILE FORMAT (one entry per line, # for comments):
#   192.168.1.1
#   sw-dist-01.lab.example.com
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   SSH enabled on target devices; 'terminal length 0' must be settable
#   Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $enable_pass, $log_file);

GetOptions(
    'h|host=s'   => \$host,
    'f|file=s'   => \$device_file,
    'u|user=s'   => \$username,
    'p|pass=s'   => \$password,
    'e|enable=s' => \$enable_pass,
    'l|log=s'    => \$log_file,
) or die "Usage: $0 [-h host|-f file] -u user -p pass [-e enable] [-l logfile]\n";

die "ERROR: Specify -h <host> or -f <file>\n" unless $host || $device_file;
die "ERROR: -u username required\n"           unless $username;
die "ERROR: -p password required\n"           unless $password;

my @devices;
if ($host) {
    push @devices, $host;
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp; s/#.*//; s/^\s+|\s+$//g;
        push @devices, $_ if $_;
    }
    close $fh;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub emit {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
emit("=" x 70 . "\n");
emit("TRUNK VLAN PRUNING AUDIT  —  $ts\n");
emit("Devices: " . scalar(@devices) . "\n");
emit("=" x 70 . "\n\n");

for my $device (@devices) {
    emit("[$device]\n");
    emit("-" x 50 . "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host     => $device,
            user     => $username,
            password => $password,
            raw_pty  => 1,
            timeout  => 15,
        );
    };
    if ($@) {
        emit("  ERROR: Cannot create SSH session: $@\n\n");
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        emit("  ERROR: SSH connection failed\n\n");
        next;
    }
    if ($login =~ /[Pp]assword|[Dd]enied|[Ff]ailed/) {
        emit("  ERROR: Authentication rejected\n\n");
        next;
    }

    $ssh->send("terminal length 0\n");
    $ssh->waitfor('\$\s*$|#\s*$', 5);

    if ($enable_pass && $login !~ /#\s*$/) {
        $ssh->send("enable\n");
        $ssh->waitfor('[Pp]assword', 5);
        $ssh->send("$enable_pass\n");
        $ssh->waitfor('#\s*$', 8);
    }

    $ssh->send("show vtp status\n");
    my $vtp = $ssh->waitfor('#\s*$', 10) // '';
    my ($vtp_domain)  = ($vtp =~ /VTP Domain Name\s*:\s*(\S+)/i);
    my ($vtp_mode)    = ($vtp =~ /VTP Operating Mode\s*:\s*(\S+)/i);
    my ($vtp_version) = ($vtp =~ /VTP [Vv]ersion\s*(?:running)?\s*:\s*(\d+)/i);
    $vtp_domain  //= 'none';
    $vtp_mode    //= 'unknown';
    $vtp_version //= '?';

    emit("  VTP domain=$vtp_domain  mode=$vtp_mode  version=$vtp_version\n");
    emit("  [WARN] VTP CLIENT — VLAN database controlled by VTP server\n")
        if lc($vtp_mode) eq 'client';

    $ssh->send("show interfaces trunk\n");
    my $trunk_out = $ssh->waitfor('#\s*$', 15) // '';

    my (%trunks, @order, $section);
    for my $line (split /\n/, $trunk_out) {
        if    ($line =~ /^Port\s+Mode\s+Encapsulation/i)       { $section = 'info'    }
        elsif ($line =~ /^Port\s+Vlans allowed on trunk/i)     { $section = 'allowed' }
        elsif ($line =~ /^Port\s+Vlans allowed and active/i)   { $section = 'active'  }
        elsif ($line =~ /^Port\s+Vlans in spanning tree/i)     { $section = 'fwd'     }
        elsif ($section eq 'info'    && $line =~ /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)/) {
            my ($p, $mode, $enc, $st) = ($1, $2, $3, $4);
            push @order, $p unless exists $trunks{$p};
            $trunks{$p} = { mode => $mode, encap => $enc, status => $st };
        }
        elsif ($section eq 'allowed' && $line =~ /^(\S+)\s+(\S+)/) { $trunks{$1}{allowed} = $2 }
        elsif ($section eq 'active'  && $line =~ /^(\S+)\s+(\S+)/) { $trunks{$1}{active}  = $2 }
    }

    if (!@order) {
        emit("  No active trunk interfaces found.\n\n");
        $ssh->send("exit\n"); $ssh->close();
        next;
    }

    emit(sprintf("  %d trunk(s) found\n\n", scalar @order));
    emit(sprintf("  %-24s %-8s %-10s  %s\n", "Interface", "Mode", "Encap", "Verdict"));
    emit("  " . "-" x 66 . "\n");

    for my $p (@order) {
        my $t       = $trunks{$p};
        my $allowed = $t->{allowed} // 'none';
        my $active  = $t->{active}  // 'none';
        my @flags;

        push @flags, 'OVER-PERMISSIVE (1-4094 or all)'
            if $allowed =~ /^1-4094$/ || $allowed =~ /\ball\b/i;

        my $na = count_vlans($allowed);
        my $aa = count_vlans($active);
        push @flags, sprintf("leakage: %d allowed vs %d active", $na, $aa)
            if $na > 0 && $aa >= 0 && ($na - $aa) > 10;

        my $verdict = @flags ? "WARN: " . join("; ", @flags) : "OK";
        emit(sprintf("  %-24s %-8s %-10s  %s\n",
            $p, $t->{mode}//'?', $t->{encap}//'?', $verdict));
        emit(sprintf("    allowed : %s\n", $allowed));
        emit(sprintf("    active  : %s\n\n", $active));
    }

    $ssh->send("exit\n");
    $ssh->close();
}

close $log_fh if $log_fh;
emit("Audit complete." . ($log_file ? " Log: $log_file" : "") . "\n");

sub count_vlans {
    my ($str) = @_;
    return 0 if !$str || $str =~ /^\s*none\s*$/i;
    my $n = 0;
    for (split /,/, $str) {
        s/\s//g;
        if (/^(\d+)-(\d+)$/) { $n += $2 - $1 + 1 }
        elsif (/^\d+$/)       { $n++ }
    }
    return $n;
}