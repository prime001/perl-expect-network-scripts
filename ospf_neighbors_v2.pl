#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use File::Spec;

=head1 ACL Audit and Compliance Check

=head2 PURPOSE
Audits all configured Access Control Lists (ACLs) on Cisco network devices,
including ACL names, rule counts, match statistics, and interface assignments.
Enables security compliance verification and ACL configuration tracking.

=head2 USAGE
acl_audit.pl --device <ip|hostname> --user <username> [--pass <password>] [--logfile <path>]
acl_audit.pl --file devices.txt --user <username> [--logfile audit.log]

=head2 EXAMPLES
acl_audit.pl --device 192.168.1.1 --user admin
acl_audit.pl --file switches.txt --user netadmin --logfile acl_results.log

=head2 PREREQUISITES
- Net::SSH::Expect module (cpan Net::SSH::Expect)
- SSH access to Cisco IOS/IOS-XE network devices
- Valid credentials with read access to show commands
- Device must support 'show access-lists' and related commands

=cut

my ($device, $file, $username, $password, $logfile);
my $port = 22;
my $timeout = 20;
my @targets;

GetOptions(
    'device=s'  => \$device,
    'file=s'    => \$file,
    'user=s'    => \$username,
    'pass=s'    => \$password,
    'logfile=s' => \$logfile,
    'port=i'    => \$port,
    'timeout=i' => \$timeout,
) or die "Invalid arguments\n";

die "Specify --device or --file\n" unless ($device || $file);
die "Username required (--user)\n" unless $username;

unless ($password) {
    print "Password: ";
    system("stty -echo") if -t STDIN;
    chomp($password = <STDIN>);
    system("stty echo") if -t STDIN;
    print "\n";
}

if ($device) {
    push @targets, $device;
} elsif ($file) {
    open my $fh, '<', $file or die "Cannot open $file: $!\n";
    while (<$fh>) {
        chomp;
        next if /^#/ || /^\s*$/;
        push @targets, $_;
    }
    close $fh;
}

my $logfh;
if ($logfile) {
    open $logfh, '>>', $logfile or warn "Cannot open logfile: $!\n";
}

sub log_output {
    my ($msg) = @_;
    print $msg;
    print $logfh $msg if defined $logfh;
}

my $timestamp = scalar localtime;
log_output("\n" . "=" x 60 . "\n");
log_output("ACL Audit Report - $timestamp\n");
log_output("=" x 60 . "\n");

foreach my $target (@targets) {
    log_output("\n[Device: $target]\n");
    
    my $ssh = Net::SSH::Expect->new(
        host => $target,
        user => $username,
        password => $password,
        port => $port,
        timeout => $timeout,
        raw_pty => 1,
    );
    
    unless ($ssh->connect()) {
        log_output("ERROR: Cannot connect\n");
        next;
    }
    
    $ssh->send('terminal length 0');
    $ssh->waitfor('.*#', 5);
    
    # Get ACL summary - count total ACLs
    my @acl_list = $ssh->exec_cmd('show access-lists');
    my $acl_count = 0;
    my %acl_stats = (permit => 0, deny => 0, total => 0);
    
    foreach my $line (@acl_list) {
        $acl_count++ if $line =~ /^(Standard|Extended|Named|IPv6|MAC)/;
        $acl_stats{permit}++ if $line =~ /\spermit\s/;
        $acl_stats{deny}++ if $line =~ /\sdeny\s/;
        $acl_stats{total}++ if $line =~ /\s(permit|deny)\s/;
    }
    
    log_output("Total ACLs configured: $acl_count\n");
    log_output("ACL Rule Summary:\n");
    log_output("  Total rules: $acl_stats{total}\n");
    log_output("  Permit rules: $acl_stats{permit}\n");
    log_output("  Deny rules: $acl_stats{deny}\n");
    
    # Get interface ACL bindings
    my @int_status = $ssh->exec_cmd('show ip interface brief');
    my $in_acl_count = 0;
    my $out_acl_count = 0;
    
    foreach my $line (@int_status) {
        $in_acl_count++ if $line =~ /inbound/;
        $out_acl_count++ if $line =~ /outbound/;
    }
    
    log_output("Interface ACL Bindings:\n");
    log_output("  Interfaces with inbound ACLs: $in_acl_count\n");
    log_output("  Interfaces with outbound ACLs: $out_acl_count\n");
    
    # Show active ACL names
    log_output("Active ACLs:\n");
    my %seen;
    foreach my $line (@acl_list) {
        if ($line =~ /^(Standard|Extended|Named|IPv6|MAC)\s+([^\s,]+)/) {
            my $name = $2;
            unless ($seen{$name}++) {
                log_output("  - $name\n");
            }
        }
    }
    
    $ssh->close();
}

close $logfh if defined $logfh;
log_output("\n" . "=" x 60 . "\n");
log_output("Audit complete\n\n");

exit 0;