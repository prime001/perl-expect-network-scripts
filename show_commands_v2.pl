```perl
#!/usr/bin/perl
=head1 NAME

acl_rule_counter.pl - Analyze and report device ACL configurations

=head1 SYNOPSIS

  ./acl_rule_counter.pl <device> [--username user] [--password pass] [--logfile path]

=head1 DESCRIPTION

Connects to network device via SSH and analyzes Access Control Lists (ACLs).
Reports on rule counts per ACL, identifies large ACLs (>100 rules), and detects
potentially unused ACLs. Outputs summary to STDOUT and optional log file.

Useful for ACL management and capacity planning.

=head1 PREREQUISITES

  - Expect module (perl -e 'use Expect')
  - SSH access to device with appropriate credentials
  - Cisco IOS/IOS-XE network device

=head1 USAGE EXAMPLES

  # Single device with defaults (reads username/password from environment)
  ./acl_rule_counter.pl 192.168.1.1

  # With explicit credentials and logging
  ./acl_rule_counter.pl 10.0.0.5 --username admin --password P@ssw0rd --logfile acl_audit.log

  # Read credentials from environment variables
  export NET_USER=admin NET_PASS=cisco
  ./acl_rule_counter.pl core-router-1

=cut

use strict;
use warnings;
use Expect;
use Getopt::Long;

my ($username, $password, $logfile);
GetOptions(
    'username=s' => \$username,
    'password=s' => \$password,
    'logfile=s'  => \$logfile,
) or die "Error parsing options\n";

my $device = shift @ARGV or die "Usage: $0 <device> [--username user] [--password pass] [--logfile path]\n";

$username ||= $ENV{NET_USER} || 'admin';
$password ||= $ENV{NET_PASS} || 'cisco';

open my $LOG, '>>', $logfile if $logfile;

sub log_msg {
    my ($msg) = @_;
    print "$msg\n";
    print $LOG "$msg\n" if $logfile;
}

eval {
    my $exp = Expect->new();
    $exp->log_stdout(0);
    $exp->timeout(20);
    
    # Connect via SSH
    $exp->spawn("ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -l $username $device")
        or die "SSH spawn failed: $!\n";
    
    # Wait for password prompt
    my $ok = $exp->expect(15, 'password:');
    die "No password prompt within 15 seconds\n" unless $ok;
    
    # Send password
    $exp->send("$password\r");
    
    # Wait for CLI prompt
    $ok = $exp->expect(15, ['#', '>']);
    die "Authentication failed or prompt timeout\n" unless $ok;
    
    log_msg("\n=== ACL Analysis Report ===");
    log_msg("Device: $device");
    log_msg("Timestamp: " . scalar(localtime()));
    log_msg("");
    
    # Retrieve ACL configuration
    $exp->send("show access-lists\r");
    $ok = $exp->expect(15, ['#', '>']);
    die "Command timeout\n" unless $ok;
    
    my @lines = split /\n/, $exp->before();
    my %acl_rules = ();
    my $current_acl = '';
    
    # Parse ACL output
    foreach my $line (@lines) {
        # Detect ACL start line
        if ($line =~ /^(?:Extended |Standard )?[Ii]P\s+access list\s+(\S+)/) {
            $current_acl = $1;
            $acl_rules{$current_acl} = 0 unless exists $acl_rules{$current_acl};
        }
        # Count permit/deny rules
        elsif ($current_acl && $line =~ /^\s+\d+\s+(?:permit|deny)/) {
            $acl_rules{$current_acl}++;
        }
    }
    
    # Display results
    log_msg("Total ACLs Found: " . scalar(keys %acl_rules));
    log_msg("");
    
    # Sort by rule count (descending)
    my @sorted_acls = sort { $acl_rules{$b} <=> $acl_rules{$a} } keys %acl_rules;
    
    my (@large, @empty);
    log_msg("ACL Rule Count Summary:");
    log_msg("-" x 50);
    
    foreach my $acl (@sorted_acls) {
        my $count = $acl_rules{$acl};
        my $status = '';
        
        if ($count > 100) {
            $status = ' [LARGE - capacity concern]';
            push @large, $acl;
        } elsif ($count == 0) {
            $status = ' [EMPTY]';
            push @empty, $acl;
        }
        
        log_msg(sprintf("  %-40s %4d rules%s", $acl, $count, $status));
    }
    
    log_msg("-" x 50);
    
    # Warnings and notes
    if (@large) {
        log_msg("\nWARNING: " . scalar(@large) . " ACL(s) exceed 100 rules:");
        foreach my $acl (@large) {
            log_msg("  - $acl (" . $acl_rules{$acl} . " rules)");
        }
    }
    
    if (@empty) {
        log_msg("\nNOTE: " . scalar(@empty) . " ACL(s) have no rules (potential cleanup candidates)");
    }
    
    # Cleanup
    $exp->send("exit\r");
    $exp->soft_close();
    
    log_msg("\nReport completed successfully");
    
} or do {
    log_msg("ERROR: $@");
    $exp->soft_close() if defined $exp;
    exit 1;
};

close $LOG if $logfile;
exit 0;
```