```perl
#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use File::Spec;

=head1 CONFIG COMPLIANCE AUDITOR

Validates network device running configurations against a set of required keywords and settings.
Useful for compliance checks, security audits, and operational standards validation.

Usage: ./031_config_compliance_auditor.pl --host 192.168.1.1 --policy policy.txt [--username admin] [--password pass] [--log audit.log]

Policy file format (one item per line):
  syslog-server 10.0.0.1
  logging buffered
  ntp server 8.8.8.8
  snmp-server community read-only
  enable secret

Prerequisites:
  - Perl modules: Net::SSH::Expect
  - SSH access to devices
  - SSH key or username/password auth
  - Policy file with required configuration keywords

=cut

my ($host, $username, $password, $policy_file, $log_file, $port, $timeout);

GetOptions(
    'host=s'     => \$host,
    'username=s' => \$username,
    'password=s' => \$password,
    'policy=s'   => \$policy_file,
    'log=s'      => \$log_file,
    'port=i'     => \$port,
    'timeout=i'  => \$timeout,
) or die "Error in command line arguments\n";

die "Host required: --host <IP or hostname>\n" unless $host;
die "Policy file required: --policy <file>\n" unless $policy_file;
die "Policy file not found: $policy_file\n" unless -f $policy_file;

$port    ||= 22;
$timeout ||= 10;
$username ||= 'admin';
$password ||= 'admin';

my @log_messages;
my $timestamp = scalar localtime;

sub log_output {
    my ($msg) = @_;
    print "$msg\n";
    push @log_messages, "[" . scalar(localtime) . "] $msg";
}

log_output("=== Config Compliance Audit: $host ($timestamp) ===");

my $ssh;
eval {
    $ssh = Net::SSH::Expect->new(
        host    => $host,
        user    => $username,
        password => $password,
        port    => $port,
        timeout => $timeout,
    );
    $ssh->login() or die "Login failed for $host";
};
if ($@) {
    log_output("ERROR: Connection failed - $@");
    write_log($log_file) if $log_file;
    exit 1;
}

log_output("Connected to $host");

my $config = '';
eval {
    $ssh->send('terminal length 0');
    $ssh->waitfor('>', 2);
    $ssh->send('show running-config');
    $config = $ssh->waitfor('>', $timeout);
};
if ($@) {
    log_output("ERROR: Failed to retrieve config - $@");
    $ssh->close();
    write_log($log_file) if $log_file;
    exit 1;
}

$ssh->close();
log_output("Retrieved running configuration");

my @required_items;
open my $fh, '<', $policy_file or die "Cannot read policy file: $!\n";
while (<$fh>) {
    chomp;
    next if /^\s*#/ or /^\s*$/;
    push @required_items, $_;
}
close $fh;

log_output("\nChecking " . scalar(@required_items) . " policy items...\n");

my ($compliant, $non_compliant) = (0, 0);
my @missing;

foreach my $item (@required_items) {
    my $found = 0;
    foreach my $line (split /\n/, $config) {
        if (index($line, $item) >= 0) {
            $found = 1;
            last;
        }
    }
    
    if ($found) {
        log_output("  [OK] $item");
        $compliant++;
    } else {
        log_output("  [MISSING] $item");
        $non_compliant++;
        push @missing, $item;
    }
}

log_output("\n=== Summary ===");
log_output("Device: $host");
log_output("Compliant: $compliant");
log_output("Non-Compliant: $non_compliant");

if (@missing) {
    log_output("\nRequired items not found:");
    foreach (@missing) {
        log_output("  - $_");
    }
}

log_output("\nCompliance Status: " . 
    ($non_compliant == 0 ? "PASS" : "FAIL"));

write_log($log_file) if $log_file;
exit($non_compliant > 0 ? 1 : 0);

sub write_log {
    my ($file) = @_;
    return unless $file;
    open my $fh, '>', $file or warn "Cannot write log: $!\n";
    print $fh join("\n", @log_messages) if $fh;
    close $fh;
    log_output("\nLog written to: $file");
}
```