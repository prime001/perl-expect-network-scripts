```perl
#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use Time::Localtime;

=head1 NAME
device_syslog_audit.pl - Audit syslog server configuration on network devices

=head1 DESCRIPTION
Connects to network devices via SSH and verifies syslog servers are properly
configured. Reports actual configuration and flags missing expected servers.

=head1 USAGE
  device_syslog_audit.pl --device 192.168.1.1 --user admin --password admin
  device_syslog_audit.pl --file inventory.txt --user netadmin --key ~/.ssh/id_rsa

=head1 PREREQUISITES
  - Net::SSH::Expect Perl module (install via: cpan Net::SSH::Expect)
  - SSH access to target devices with appropriate credentials
  - Cisco IOS, IOS-XE, or NX-OS devices
  - Network connectivity to target devices

=cut

my ($device, $device_file, $ssh_user, $ssh_pass, $ssh_key, $logfile, $expected);

GetOptions(
    'device=s'   => \$device,
    'file=s'     => \$device_file,
    'user=s'     => \$ssh_user,
    'password=s' => \$ssh_pass,
    'key=s'      => \$ssh_key,
    'logfile=s'  => \$logfile,
    'expected=s' => \$expected,
    'help'       => sub { print_help(); exit 0; },
) or die "Invalid arguments\n";

die "Must specify --device or --file\n" unless ($device || $device_file);
die "Must specify --user\n" unless $ssh_user;
die "Must specify --password or --key\n" unless ($ssh_pass || $ssh_key);

$logfile ||= 'syslog_audit.log';
my @devices = $device ? ($device) : read_device_file($device_file);
my %expected_servers = map { $_ => 1 } split(/,/, ($expected || ''));

open(my $log, '>>', $logfile) or die "Cannot open logfile: $!\n";
my $ts = scalar(localtime());
print $log "\n" . "="x60 . "\n";
print $log "Syslog Configuration Audit - $ts\n";
print $log "="x60 . "\n";

foreach my $host (@devices) {
    check_syslog_config($host, $ssh_user, $ssh_pass, $ssh_key, $log, %expected_servers);
}

close($log);
print "Audit complete. Results written to $logfile\n";

sub read_device_file {
    my ($filename) = @_;
    open(my $fh, '<', $filename) or die "Cannot open $filename: $!\n";
    my @hosts;
    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^#/ || $line =~ /^\s*$/;
        push @hosts, $line;
    }
    close($fh);
    return @hosts;
}

sub check_syslog_config {
    my ($hostname, $user, $pass, $key, $log, %expected) = @_;
    
    print "[$hostname] ";
    print $log "\nDevice: $hostname\n";
    print $log "-" x 40 . "\n";
    
    my $ssh;
    eval {
        my %ssh_opts = (
            host => $hostname,
            user => $user,
            port => 22,
            timeout => 15,
            raw_pty => 1,
        );
        
        if ($key) {
            $ssh_opts{key_path} = $key;
        } else {
            $ssh_opts{password} = $pass;
        }
        
        $ssh = Net::SSH::Expect->new(%ssh_opts);
        $ssh->login() or die "SSH login failed\n";
    };
    
    if ($@) {
        print "FAILED\n";
        print $log "Status: FAILED - Connection error: $@";
        return;
    }
    
    eval {
        $ssh->send("terminal length 0");
        $ssh->waitfor('.*[>#]', 5);
        
        $ssh->send("show logging");
        my @output = $ssh->waitfor('.*[>#]', 10);
        
        my @syslog_servers;
        foreach my $line (@output) {
            if ($line =~ /logging\s+host\s+([\d\.]+)/ ||
                $line =~ /logging\s+server\s+([\d\.]+)/ ||
                $line =~ /Syslog\s+logging\s+servers.*?:\s*([\d\.]+)/i) {
                push @syslog_servers, $1;
            }
        }
        
        if (@syslog_servers) {
            print "OK\n";
            my $servers = join(", ", @syslog_servers);
            print $log "Status: OK\n";
            print $log "Configured servers: $servers\n";
            
            if (%expected) {
                my @missing;
                foreach my $exp (keys %expected) {
                    push @missing, $exp unless grep { $_ eq $exp } @syslog_servers;
                }
                
                if (@missing) {
                    print $log "WARNING: Missing expected servers: " . join(", ", @missing) . "\n";
                } else {
                    print $log "All expected servers found\n";
                }
            }
        } else {
            print "WARNING\n";
            print $log "Status: WARNING - No syslog servers configured\n";
        }
        
        $ssh->close();
    };
    
    if ($@) {
        print $log "Status: ERROR - $@";
    }
}

sub print_help {
    print <<EOF;
device_syslog_audit.pl - Audit syslog configuration on network devices

USAGE:
    device_syslog_audit.pl --device HOST [options]
    device_syslog_audit.pl --file FILENAME [options]

REQUIRED OPTIONS:
    --device HOSTNAME    Single device IP or hostname
    --file FILENAME      Text file with one device per line
    --user USERNAME      SSH username
    --password PASS      SSH password
    --key KEYFILE        SSH private key file (instead of password)

OPTIONAL OPTIONS:
    --logfile FILE       Output log file (default: syslog_audit.log)
    --expected SERVERS   Expected servers comma-separated (10.0.0.1,10.0.0.2)

EXAMPLES:
    device_syslog_audit.pl --device 10.0.0.1 --user admin --password admin
    device_syslog_audit.pl --file devices.txt --user netadmin --key ~/.ssh/id_rsa

EOF
}
```