The user's explicit instruction is to "Output ONLY the script content" — that takes precedence over the brainstorming workflow here. Writing the inventory-collection script now.

#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

# =============================================================================
# cdp_lldp_neighbors.pl - CDP/LLDP Neighbor Discovery Collector
#
# Purpose:
#   Connects to Cisco IOS/IOS-XE/NX-OS devices via SSH and collects CDP and
#   LLDP neighbor detail, building a structured neighbor topology report.
#   Useful for verifying cabling, auditing topology, and documenting
#   layer-2/layer-3 adjacencies before/after maintenance windows.
#
# Usage:
#   Single device:   ./cdp_lldp_neighbors.pl -h 192.168.1.1
#   Device list:     ./cdp_lldp_neighbors.pl -f devices.txt
#   With logging:    ./cdp_lldp_neighbors.pl -f devices.txt -l neighbors.log
#   Custom creds:    ./cdp_lldp_neighbors.pl -h 10.0.0.1 -u admin -p secret
#
# Prerequisites:
#   - Perl modules: Net::SSH::Expect, Getopt::Long (cpan install Net::SSH::Expect)
#   - SSH access to target devices
#   - 'cdp run' or 'lldp run' enabled on target devices
#   - Credentials with at least read-only privilege
#
# Environment variables (optional, override CLI prompts):
#   NET_USER, NET_PASS, NET_ENABLE
# =============================================================================

my ($host_arg, $file_arg, $log_file, $username, $password, $enable_pass);
my $timeout = 30;

GetOptions(
    'h|host=s'    => \$host_arg,
    'f|file=s'    => \$file_arg,
    'l|log=s'     => \$log_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'e|enable=s'  => \$enable_pass,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 [-h host | -f file] [-l logfile] [-u user] [-p pass] [-e enable]\n";

die "Specify -h <host> or -f <file>\n" unless $host_arg || $file_arg;

$username    ||= $ENV{NET_USER}   || do { print "Username: "; chomp(my $u = <STDIN>); $u };
$password    ||= $ENV{NET_PASS}   || do { system("stty -echo"); print "Password: "; chomp(my $p = <STDIN>); system("stty echo"); print "\n"; $p };
$enable_pass ||= $ENV{NET_ENABLE} || $password;

my @devices;
if ($host_arg) {
    push @devices, $host_arg;
} else {
    open(my $fh, '<', $file_arg) or die "Cannot open device file '$file_arg': $!\n";
    while (<$fh>) { chomp; push @devices, $_ if /\S/ && !/^#/; }
    close $fh;
}

my $LOG;
if ($log_file) {
    open($LOG, '>', $log_file) or die "Cannot open log file '$log_file': $!\n";
}

my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
output("=" x 70);
output("CDP/LLDP Neighbor Collection  --  $timestamp");
output("=" x 70);

for my $device (@devices) {
    output("\n[ Device: $device ]");
    collect_neighbors($device);
}

close $LOG if $LOG;

sub collect_neighbors {
    my ($host) = @_;

    my $ssh = Net::SSH::Expect->new(
        host        => $host,
        user        => $username,
        password     => $password,
        raw_pty     => 1,
        timeout     => $timeout,
    );

    eval {
        my $login = $ssh->login();
        unless ($login =~ /[>#]/) {
            die "Authentication failed or unexpected prompt on $host\n";
        }
    };
    if ($@) {
        output("  ERROR connecting to $host: $@");
        return;
    }

    # Enter enable mode if at user-exec prompt
    my $prompt = $ssh->exec("") // "";
    if ($prompt =~ />/) {
        $ssh->send("enable");
        $ssh->waitfor('Password:.*$', 5);
        $ssh->send($enable_pass);
        $ssh->waitfor('[#]', 10) or do { output("  ERROR: enable mode failed on $host"); $ssh->close(); return; };
    }

    # Disable paging
    $ssh->exec("terminal length 0");

    for my $proto ('cdp', 'lldp') {
        my $cmd    = "show ${proto} neighbors detail";
        my $output = $ssh->exec($cmd);

        unless (defined $output && length $output > 10) {
            output("  ${\uc($proto)}: no output or not enabled");
            next;
        }

        if ($output =~ /Invalid input|% Unknown command/i) {
            output("  ${\uc($proto)}: not supported on this platform");
            next;
        }

        my @neighbors = parse_neighbors($output, $proto);
        if (!@neighbors) {
            output("  ${\uc($proto)}: no neighbors found");
            next;
        }

        output("  ${\uc($proto)} Neighbors (" . scalar(@neighbors) . " found):");
        output(sprintf("    %-28s %-20s %-20s %-16s", "Device ID", "Local Intf", "Remote Intf", "Platform"));
        output("    " . "-" x 86);
        for my $n (@neighbors) {
            output(sprintf("    %-28s %-20s %-20s %-16s",
                substr($n->{device_id} // "unknown", 0, 27),
                substr($n->{local_intf} // "unknown", 0, 19),
                substr($n->{remote_intf} // "unknown", 0, 19),
                substr($n->{platform} // "unknown", 0, 15),
            ));
        }
    }

    $ssh->exec("exit");
    $ssh->close();
}

sub parse_neighbors {
    my ($raw, $proto) = @_;
    my @neighbors;
    my %cur;

    for my $line (split /\n/, $raw) {
        if ($proto eq 'cdp') {
            if ($line =~ /^Device ID:\s*(.+)/)           { %cur = (); $cur{device_id}   = $1; }
            elsif ($line =~ /Interface:\s*(\S+),\s*Port ID.*?:\s*(\S+)/) { $cur{local_intf} = $1; $cur{remote_intf} = $2; }
            elsif ($line =~ /Platform:\s*([^,]+)/)        { $cur{platform} = $1; }
            elsif ($line =~ /^-{5,}/ && $cur{device_id}) { push @neighbors, {%cur}; %cur = (); }
        } else {
            if ($line =~ /System Name:\s*(.+)/)           { %cur = (); $cur{device_id}   = $1; }
            elsif ($line =~ /Local Intf:\s*(\S+)/)        { $cur{local_intf}  = $1; }
            elsif ($line =~ /Port id:\s*(\S+)/)           { $cur{remote_intf} = $1; }
            elsif ($line =~ /System Description:/)        { $cur{platform}    = "see desc"; }
            elsif ($line =~ /^-{5,}/ && $cur{device_id}) { push @neighbors, {%cur}; %cur = (); }
        }
    }
    push @neighbors, {%cur} if $cur{device_id};
    return @neighbors;
}

sub output {
    my ($msg) = @_;
    print "$msg\n";
    print $LOG "$msg\n" if $LOG;
}