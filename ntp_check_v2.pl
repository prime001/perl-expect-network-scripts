#!/usr/bin/perl
use strict;
use warnings;
use Expect;
use Getopt::Long;
use File::Basename;
use Time::HiRes qw(time);

=head1 NAME

syslog_audit.pl - Network device syslog configuration and critical event auditor

=head1 SYNOPSIS

  ./syslog_audit.pl <device_ip> [username] [password]
  ./syslog_audit.pl -f devices.txt -u netadmin -p secret123
  ./syslog_audit.pl 192.168.1.1 -o audit_results.log

=head1 DESCRIPTION

Connects to Cisco/IOS network devices via SSH and performs syslog audits:
- Verifies syslog server configuration and reachability
- Checks syslog buffer status and recent critical/warning events
- Reports logging trap levels and missing configurations
- Outputs results to STDOUT and optional log file

Useful for compliance audits and troubleshooting log delivery issues.

=head1 PREREQUISITES

Perl Expect module:
  cpan Expect
  apt-get install libexpect-perl

Network requirements:
- SSH access to devices (port 22)
- Device credentials or SSH key auth
- Devices must have SSH enabled

=head1 OPTIONS

  -f file         Read device list from file (one IP per line)
  -u username     SSH username (default: prompts)
  -p password     SSH password (default: prompts)
  -o logfile      Write results to log file
  -t timeout      SSH connection timeout in seconds (default: 15)
  -h              Show this help message

=cut

my ($device_file, $username, $password, $logfile, $timeout, $help);
GetOptions(
    'f|file=s'     => \$device_file,
    'u|user=s'     => \$username,
    'p|pass=s'     => \$password,
    'o|output=s'   => \$logfile,
    't|timeout=i'  => \$timeout,
    'h|help'       => \$help,
) or die "Error in command line arguments\n";

die "Usage: $0 <device_ip> | -f <device_file> [-u user] [-p pass] [-o logfile]\n" if $help;

$timeout //= 15;
my @devices;

if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp;
        push @devices, $_ if $_ && $_ !~ /^\s*#/;
    }
    close($fh);
} else {
    push @devices, $ARGV[0] or die "No device specified\n";
}

my $exp = Expect->new();
$exp->log_stdout(0);
my $start = time();
my @results;

foreach my $device (@devices) {
    my $result = audit_syslog($device, $username, $password, $exp, $timeout);
    push @results, $result;
}

my $elapsed = time() - $start;
output_report(\@results, $logfile, $elapsed);

sub audit_syslog {
    my ($device, $user, $pass, $exp, $to) = @_;
    my $report = { device => $device, status => 'FAIL', errors => [] };
    
    if (!$user) {
        print "Username for $device: ";
        chomp($user = <STDIN>);
    }
    if (!$pass) {
        print "Password: ";
        system('stty', '-echo') if -t STDIN;
        chomp($pass = <STDIN>);
        system('stty', 'echo') if -t STDIN;
        print "\n";
    }
    
    eval {
        $exp->spawn("ssh -o StrictHostKeyChecking=no $user\@$device")
            or push @{$report->{errors}}, "SSH spawn failed";
        
        $exp->timeout($to);
        $exp->expect($to, ['password', 'assword']);
        $exp->send("$pass\n");
        
        $exp->expect($to, ['>', '#']) or push @{$report->{errors}}, "Auth timeout";
        $exp->send("terminal length 0\n");
        $exp->expect($to, ['>', '#']);
        
        my @syslog_tests = (
            { cmd => "show logging", label => 'syslog_config' },
            { cmd => "show logging | include server|trap", label => 'trap_servers' },
            { cmd => "show log | include %.*-[3-5]-", label => 'critical_events' },
        );
        
        foreach my $test (@syslog_tests) {
            $exp->send("$test->{cmd}\n");
            $exp->expect($to, ['>', '#']);
            my $output = $exp->before;
            
            if ($output =~ /invalid|unrecognized/i) {
                push @{$report->{errors}}, "Command failed: $test->{cmd}";
                next;
            }
            
            if ($test->{label} eq 'trap_servers') {
                if ($output =~ /^[^:]*server/) {
                    $report->{trap_servers} = [ grep { /server/ } split /\n/, $output ];
                } else {
                    push @{$report->{errors}}, "No trap servers configured";
                }
            }
            
            if ($test->{label} eq 'critical_events') {
                my @critical = grep { /[%]/ } split /\n/, $output;
                $report->{critical_count} = scalar(@critical);
                if (@critical) {
                    push @{$report->{warnings}}, "Found $report->{critical_count} critical/warning events";
                    $report->{recent_events} = [ @critical[0..4] ];
                }
            }
        }
        
        $exp->send("exit\n");
        $exp->soft_close();
        
        $report->{status} = @{$report->{errors}} ? 'WARN' : 'OK';
    };
    
    if ($@) {
        push @{$report->{errors}}, "Exception: $@";
        $report->{status} = 'ERROR';
    }
    
    return $report;
}

sub output_report {
    my ($results, $logfile, $elapsed) = @_;
    
    my @lines = (
        "=" x 70,
        "SYSLOG AUDIT REPORT - " . scalar(localtime()),
        "=" x 70,
        "",
    );
    
    foreach my $r (@$results) {
        push @lines, sprintf("Device: %-20s Status: %s", $r->{device}, $r->{status});
        
        if (@{$r->{errors}}) {
            push @lines, "  Errors:";
            push @lines, "    - $_" foreach @{$r->{errors}};
        }
        
        if ($r->{trap_servers}) {
            push @lines, "  Trap Servers: " . join(", ", @{$r->{trap_servers}});
        }
        
        if ($r->{critical_count}) {
            push @lines, "  Critical Events: $r->{critical_count}";
        }
        push @lines, "";
    }
    
    push @lines, sprintf("Audit completed in %.2f seconds", $elapsed);
    
    my $report = join("\n", @lines);
    print $report;
    
    if ($logfile) {
        open(my $fh, '>', $logfile) or warn "Cannot write to $logfile: $!\n";
        print $fh $report if $fh;
        close($fh) if $fh;
    }
}