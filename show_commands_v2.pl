```perl
#!/usr/bin/perl
=head1
SPANNING TREE PROTOCOL (STP) AUDIT SCRIPT
Audits STP topology, bridge priorities, port roles, and topology change counts
PURPOSE: Collect and analyze Spanning Tree configuration and operational status
USAGE: ./stp_audit.pl --device 192.168.1.1 [--user admin] [--pass secret] [--log stp_audit.log]
       ./stp_audit.pl --file devices.txt [--user admin] [--pass secret]
PREREQUISITES: Perl Expect module (cpan Expect), SSH access with privileged exec
OUTPUT: Console summary + detailed log file showing bridge priority, port roles, and topology health
=cut

use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($device, $device_file, $user, $pass, $logfile, $timeout);
GetOptions(
    'device=s'  => \$device,
    'file=s'    => \$device_file,
    'user=s'    => \$user,
    'pass=s'    => \$pass,
    'log=s'     => \$logfile,
    'timeout=i' => \$timeout,
    'help'      => sub { print_usage(); exit 0; }
) or die "Error in command line arguments\n";

$user    //= 'admin';
$timeout //= 10;

die "Usage: stp_audit.pl --device <IP> | --file <list>\n" unless $device || $device_file;

my @devices = $device ? ($device) : do {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    my @list = grep { !/^#/ && !/^\s*$/ } <$fh>;
    chomp @list;
    close $fh;
    @list;
};

my $log_fh;
if ($logfile) {
    open $log_fh, '>>', $logfile or die "Cannot open $logfile: $!\n";
    print $log_fh "\n" . "="x70 . "\n";
    print $log_fh "STP AUDIT - " . strftime("%Y-%m-%d %H:%M:%S", localtime) . "\n";
    print $log_fh "="x70 . "\n";
}

foreach my $host (@devices) {
    audit_stp_device($host, $user, $pass, $timeout, $log_fh);
}

close $log_fh if $log_fh;
print "\n[*] Audit complete.\n";

sub audit_stp_device {
    my ($host, $user, $pass, $timeout, $log) = @_;
    
    print "\n[*] Connecting to $host...\n";
    log_output($log, "[*] Connecting to $host");
    
    my $exp = Expect->new();
    $exp->log_stdout(0);
    $exp->set_timeout($timeout);
    
    eval {
        $exp->spawn("ssh -o ConnectTimeout=$timeout -o StrictHostKeyChecking=no $user\@$host")
            or die "Cannot spawn SSH: $!\n";
        
        $exp->expect($timeout, ['password:', 'Password:'])
            or die "No password prompt\n";
        
        $exp->send("$pass\n");
        $exp->expect($timeout, ['#', '>', '\$'])
            or die "No command prompt after authentication\n";
        
        $exp->send("terminal length 0\n");
        $exp->expect($timeout, ['#', '>', '\$']);
        
        my @commands = (
            'show spanning-tree summary',
            'show spanning-tree bridge',
            'show spanning-tree interface status'
        );
        
        print "\n[+] STP Audit Results: $host\n";
        log_output($log, "\n[+] STP Audit Results: $host");
        
        foreach my $cmd (@commands) {
            $exp->clear_accumulators();
            $exp->send("$cmd\n");
            $exp->expect($timeout, ['#', '>', '\$']);
            my $output = $exp->before();
            
            print "\n[$cmd]\n";
            log_output($log, "\n[$cmd]");
            
            my @lines = split /\n/, $output;
            foreach my $line (@lines) {
                next if $line =~ /^\s*$/ || $line =~ /^$cmd$/ || $line =~ /^$host/;
                
                if ($line =~ /Bridge|Priority|Port|Role|State|Cost|VLAN|Topology|Changes/) {
                    my $display = "  $line";
                    print "$display\n";
                    log_output($log, $display);
                }
            }
        }
        
        $exp->send("exit\n");
        $exp->soft_close();
        print "[+] Completed $host\n";
        log_output($log, "[+] Completed $host");
        
    } or do {
        my $error = $@;
        print "[-] Error connecting to $host: $error\n";
        log_output($log, "[-] Error connecting to $host: $error");
    };
}

sub log_output {
    my ($fh, $msg) = @_;
    return unless $fh;
    print $fh "$msg\n";
}

sub print_usage {
    print <<'EOF';
STP AUDIT - Spanning Tree Protocol Configuration and Status Audit

USAGE:
  stp_audit.pl --device <IP|hostname> [--user admin] [--pass secret] [--log stp.log]
  stp_audit.pl --file devices.txt [--user admin] [--pass secret] [--log stp.log]

OPTIONS:
  --device    Target device IP or hostname
  --file      File containing device list (one per line, # for comments)
  --user      SSH username (default: admin)
  --pass      SSH password
  --log       Optional output log file (appends results)
  --timeout   SSH timeout in seconds (default: 10)
  --help      Show this help message

EXAMPLES:
  stp_audit.pl --device 10.1.1.1 --user admin --pass MyPass123 --log results.log
  stp_audit.pl --file switches.txt --user netadmin --log stp_audit.log

PREREQUISITES:
  - Perl Expect module: cpan Expect
  - SSH access to Cisco/vendor network devices
  - User account with exec/privileged access
  - Device running Spanning Tree (PVST+, RSTP, MST)

OUTPUT:
  Displays and logs: Bridge priority, STP mode, port roles/states, topology changes
EOF
}
```