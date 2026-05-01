```perl
#!/usr/bin/perl
use strict;
use warnings;
use Expect;
use Getopt::Long;
use Time::Piece;
use IO::Handle;

=head1 PORT CHANNEL AUDIT SCRIPT

Purpose:
  Audits port channel (EtherChannel/LAG) configurations and status on network devices.
  Reports channel status, member interfaces, protocol type, and identifies misconfigurations.

Usage:
  ./port_channel_audit.pl --host <device_ip> [--user <username>] [--pass <password>] [--log <file>]
  ./port_channel_audit.pl --file <device_list.txt>

Prerequisites:
  - Expect Perl module (install via: cpan Expect)
  - SSH access to network devices
  - Valid username/password credentials
  - Devices must support 'show etherchannel' commands (Cisco IOS/IOS-XE/NX-OS)

Examples:
  perl port_channel_audit.pl --host 192.168.1.1 --user netadmin --pass mypass123
  perl port_channel_audit.pl --file devices.txt --log port_channels_$(date +%Y%m%d).log

=cut

my ($host, $hostfile, $username, $password, $logfile, $timeout, $help);

GetOptions(
    'host=s'     => \$host,
    'file=s'     => \$hostfile,
    'user=s'     => \$username,
    'pass=s'     => \$password,
    'log=s'      => \$logfile,
    'timeout=i'  => \$timeout,
    'help'       => \$help,
) or die "Error in command line arguments\n";

if ($help) {
    print "Port Channel Audit Tool\n";
    print "Usage: $0 --host <ip> | --file <devices.txt> [--user u] [--pass p] [--log l]\n";
    exit 0;
}

die "Specify --host or --file\n" unless $host || $hostfile;

$timeout //= 30;
$username //= 'admin';

my @targets;
if ($host) {
    push @targets, $host;
} else {
    open my $fh, '<', $hostfile or die "Cannot open $hostfile: $!\n";
    while (<$fh>) {
        chomp;
        next if /^#|^\s*$/;
        push @targets, $_;
    }
    close $fh;
}

my $logfh = \*STDOUT;
if ($logfile) {
    open $logfh, '>>', $logfile or die "Cannot open $logfile: $!\n";
    $logfh->autoflush(1);
}

my $timestamp = localtime->strftime('%Y-%m-%d %H:%M:%S');
print $logfh "[*] Port Channel Audit - $timestamp\n";
print $logfh "=" x 70 . "\n";

foreach my $target (@targets) {
    audit_device($target, $logfh);
}

close $logfh if $logfile;

sub audit_device {
    my ($device, $fh) = @_;
    
    print $fh "\n[TARGET] $device\n";
    print STDOUT "[*] Auditing $device...\n";
    
    my $exp = Expect->new();
    $exp->log_stdout(0);
    $exp->timeout($timeout);
    
    eval {
        $exp->spawn("ssh", "-o", "StrictHostKeyChecking=no",
                   "-o", "UserKnownHostsFile=/dev/null", "$username\@$device")
            or die "SSH spawn failed: $!\n";
        
        $exp->expect($timeout,
            [qr/[Pp]assword:/, sub { $_[0]->send("$password\n"); exp_continue; }],
            [qr/[>#]/, sub { }],
        ) or die "Login timeout\n";
        
        $exp->send("enable\n");
        $exp->expect(1, [qr/[Pp]assword:/, sub { $_[0]->send("$password\n"); exp_continue; }],
                       [qr/#/, sub { }]);
        
        $exp->send("terminal length 0\n");
        $exp->expect(1, qr/#/);
        
        $exp->send("show etherchannel summary\n");
        $exp->expect($timeout, qr/#/);
        my $output = $exp->before();
        
        print $fh "[SUMMARY]\n";
        foreach my $line (split /\n/, $output) {
            next if $line =~ /^show etherchannel|^#|^\s*$/;
            print $fh "  $line\n";
        }
        
        if ($output =~ /\(D\)|down|fail|suspend/i) {
            print $fh "[ALERT] Down or suspended members detected\n";
        }
        
        $exp->send("show etherchannel detail | include 'Protocol\\|Group'\n");
        $exp->expect($timeout, qr/#/);
        my $detail = $exp->before();
        
        my %protocols;
        foreach my $line (split /\n/, $detail) {
            $protocols{$1}++ if $line =~ /Protocol\s*:\s+(\w+)/i;
        }
        
        print $fh "[PROTOCOL] " . join(", ", sort keys %protocols) . "\n" if %protocols;
        
        $exp->send("exit\n");
        $exp->expect(1);
        $exp->close();
        
        print $fh "[+] Completed successfully\n";
        
    } or do {
        my $error = $@;
        chomp $error;
        print $fh "[-] Error: $error\n";
        print STDOUT "[!] Error on $device: $error\n";
        $exp->close() if defined $exp;
    };
}

1;
```