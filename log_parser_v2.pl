#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# arp_table.pl - Network Device ARP Table Collector and Analyzer
#
# PURPOSE:
#   Connects to Cisco IOS/IOS-XE devices via SSH and retrieves ARP table data.
#   Parses entries to identify duplicate MACs (potential IP spoofing), incomplete
#   ARP entries (connectivity issues), and builds a host inventory from ARP data.
#
# USAGE:
#   Single device:   ./arp_table.pl --host 192.168.1.1
#   Multiple devices: ./arp_table.pl --file devices.txt
#   With logging:    ./arp_table.pl --host 192.168.1.1 --logfile arp_audit.log
#   Custom creds:    ./arp_table.pl --host 192.168.1.1 --user admin --pass secret
#
# PREREQUISITES:
#   cpan Net::SSH::Expect
#   SSH access to target devices (IOS/IOS-XE)
#   Credentials with 'show' privilege (priv 1+)
#
# OUTPUT:
#   ARP table summary per device, flagged anomalies, optional CSV log
# =============================================================================

my ($opt_host, $opt_file, $opt_user, $opt_pass, $opt_logfile, $opt_timeout);
$opt_user    = $ENV{NET_USER}  || 'admin';
$opt_pass    = $ENV{NET_PASS}  || 'cisco';
$opt_timeout = 15;

GetOptions(
    'host=s'    => \$opt_host,
    'file=s'    => \$opt_file,
    'user=s'    => \$opt_user,
    'pass=s'    => \$opt_pass,
    'logfile=s' => \$opt_logfile,
    'timeout=i' => \$opt_timeout,
) or die "Usage: $0 --host <ip> | --file <file> [--user u] [--pass p] [--logfile f]\n";

die "Specify --host or --file\n" unless $opt_host || $opt_file;

my @devices;
if ($opt_host) {
    push @devices, $opt_host;
} else {
    open(my $fh, '<', $opt_file) or die "Cannot open $opt_file: $!\n";
    @devices = grep { /\S/ && !/^#/ } map { chomp; $_ } <$fh>;
    close $fh;
}

my $log_fh;
if ($opt_logfile) {
    open($log_fh, '>>', $opt_logfile) or die "Cannot open logfile $opt_logfile: $!\n";
    print $log_fh "# ARP audit started: " . strftime("%Y-%m-%d %H:%M:%S", localtime) . "\n";
    print $log_fh "# device,ip_address,mac_address,interface,type,age,flag\n";
}

sub log_out {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

for my $host (@devices) {
    log_out("\n=== ARP Table: $host ===\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $host,
            user        => $opt_user,
            password    => $opt_pass,
            ssh_option  => '-o StrictHostKeyChecking=no -o ConnectTimeout=10',
            timeout     => $opt_timeout,
            raw_pty     => 1,
        );
    };
    if ($@) {
        log_out("[ERROR] Cannot create SSH session to $host: $@\n");
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        log_out("[ERROR] Login failed for $host (check credentials or SSH access)\n");
        next;
    }
    if ($login =~ /password|denied|fail/i) {
        log_out("[ERROR] Authentication rejected on $host\n");
        next;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('\$|#', $opt_timeout) or do {
        log_out("[ERROR] Prompt not found after terminal length on $host\n");
        next;
    };

    $ssh->send("show ip arp");
    my $output = $ssh->waitfor('\$|#', $opt_timeout);
    unless (defined $output) {
        log_out("[ERROR] Timeout waiting for ARP output on $host\n");
        next;
    }

    $ssh->send("exit");

    my %mac_to_ips;
    my @entries;
    my $total = 0;
    my $incomplete = 0;

    for my $line (split /\n/, $output) {
        # IOS format: Protocol  Address  Age(min)  Hardware Addr  Type  Interface
        # Internet   10.0.0.1    -       aabb.cc00.0100  ARPA  Gi0/0
        next unless $line =~ /^Internet\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)/;
        my ($ip, $age, $mac, $type, $iface) = ($1, $2, $3, $4, $5);
        $total++;

        if ($mac =~ /^Incom/i) {
            $incomplete++;
            my $flag = "INCOMPLETE";
            log_out(sprintf("  %-18s %-20s %-15s %s\n", $ip, $mac, $iface, "[$flag]"));
            print $log_fh "$host,$ip,$mac,$iface,$type,$age,$flag\n" if $log_fh;
            next;
        }

        push @{ $mac_to_ips{lc $mac} }, $ip;
        push @entries, { ip => $ip, mac => lc($mac), age => $age, iface => $iface, type => $type };
    }

    my %dup_macs = map { $_ => $mac_to_ips{$_} }
                   grep { scalar @{ $mac_to_ips{$_} } > 1 } keys %mac_to_ips;

    for my $entry (@entries) {
        my $flag = exists $dup_macs{ $entry->{mac} } ? "DUPLICATE_MAC" : "ok";
        my $display = $flag eq "ok" ? "" : "[$flag -> " . join(", ", @{ $dup_macs{ $entry->{mac} } }) . "]";
        log_out(sprintf("  %-18s %-20s %-15s %s\n", $entry->{ip}, $entry->{mac}, $entry->{iface}, $display));
        print $log_fh "$host,$entry->{ip},$entry->{mac},$entry->{iface},$entry->{type},$entry->{age},$flag\n" if $log_fh;
    }

    log_out(sprintf("\n  Summary: %d total entries, %d incomplete, %d duplicate MACs\n",
        $total, $incomplete, scalar keys %dup_macs));
    log_out("  Flagged MACs (possible IP conflict/spoofing):\n") if %dup_macs;
    for my $mac (sort keys %dup_macs) {
        log_out(sprintf("    %s => %s\n", $mac, join(", ", @{ $dup_macs{$mac} })));
    }
}

close $log_fh if $log_fh;
log_out("\nDone. " . strftime("%Y-%m-%d %H:%M:%S", localtime) . "\n");