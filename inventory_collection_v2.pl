I'll write a CDP/LLDP neighbor discovery script — that's a practical inventory-collection task not covered by the existing scripts.

```perl
#!/usr/bin/perl
#
# cdp_lldp_neighbors.pl — Cisco CDP/LLDP Neighbor Discovery
#
# Purpose:
#   Connects to one or more network devices via SSH and collects CDP and LLDP
#   neighbor tables. Useful for topology documentation, audit prep, and verifying
#   neighbor relationships after network changes.
#
# Usage:
#   perl cdp_lldp_neighbors.pl -h 192.168.1.1 [-u admin] [-p secret] [-o neighbors.txt]
#   perl cdp_lldp_neighbors.pl -f devices.txt [-u admin] [-p secret] [-o neighbors.txt]
#
# devices.txt format (one per line):
#   192.168.1.1
#   192.168.1.2  admin  mysecret
#
# Prerequisites:
#   cpanm Net::SSH::Expect
#   SSH key auth or password auth must be configured on target devices
#   'terminal length 0' privilege required (enable not needed for show commands)

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $username, $password, $device_file, $output_file, $help);
my $timeout = 20;

GetOptions(
    'host|h=s'    => \$host,
    'user|u=s'    => \$username,
    'pass|p=s'    => \$password,
    'file|f=s'    => \$device_file,
    'output|o=s'  => \$output_file,
    'timeout|t=i' => \$timeout,
    'help'        => \$help,
) or die usage();

print usage() and exit 0 if $help;
die usage() unless $host || $device_file;

$username //= $ENV{NET_USER} // die "Username required (-u or NET_USER env)\n";
$password //= $ENV{NET_PASS} // die "Password required (-p or NET_PASS env)\n";

my $log_fh;
if ($output_file) {
    open($log_fh, '>', $output_file) or die "Cannot open $output_file: $!\n";
}

my @devices;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) {
        chomp; next if /^\s*#/ || /^\s*$/;
        my ($dev_host, $dev_user, $dev_pass) = split /\s+/, $_, 3;
        push @devices, {
            host => $dev_host,
            user => $dev_user // $username,
            pass => $dev_pass // $password,
        };
    }
    close $fh;
} else {
    push @devices, { host => $host, user => $username, pass => $password };
}

my $stamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
output("# CDP/LLDP Neighbor Report — $stamp\n");

for my $dev (@devices) {
    output("\n" . "=" x 60 . "\n");
    output("Device: $dev->{host}\n");
    output("=" x 60 . "\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $dev->{host},
            user        => $dev->{user},
            password    => $dev->{pass},
            raw_pty     => 1,
            timeout     => $timeout,
        );
    };
    if ($@) {
        output("ERROR: Failed to create SSH session — $@\n");
        next;
    }

    my $login = eval { $ssh->login() };
    if ($@ || !defined $login) {
        output("ERROR: Authentication failed for $dev->{host}\n");
        next;
    }
    if ($login =~ /[Pp]assword|[Aa]uth/i && $login !~ /[>#]/) {
        output("ERROR: Bad credentials for $dev->{host}\n");
        next;
    }

    $ssh->send('terminal length 0');
    $ssh->waitfor('[>#]', $timeout) or output("WARN: prompt timeout after terminal length 0\n");

    for my $cmd ('show cdp neighbors detail', 'show lldp neighbors detail') {
        $ssh->send($cmd);
        my $out = $ssh->waitfor('[>#]', $timeout);
        if (!defined $out) {
            output("WARN: Timeout waiting for output of '$cmd'\n");
            next;
        }
        if ($out =~ /(?:Invalid|error|not enabled)/i) {
            output("  [$cmd] not available or disabled\n");
            next;
        }
        output("\n--- $cmd ---\n");
        output(clean_output($out, $cmd));
    }

    $ssh->send('exit');
    $ssh->close();
}

close $log_fh if $log_fh;
print "\nOutput written to $output_file\n" if $output_file;

sub clean_output {
    my ($text, $cmd) = @_;
    $text =~ s/\r//g;
    my @lines = grep { !/^\s*$cmd\s*$/ && !/^[A-Za-z0-9\-]+[>#]\s*$/ } split /\n/, $text;
    return join("\n", @lines) . "\n";
}

sub output {
    my $text = shift;
    print $text;
    print $log_fh $text if $log_fh;
}

sub usage {
    return <<'END';
Usage: cdp_lldp_neighbors.pl -h <host> | -f <file> [-u user] [-p pass] [-o outfile] [-t timeout]
  -h  Single device IP or hostname
  -f  File with device list (host [user] [pass] per line)
  -u  SSH username (or set NET_USER env)
  -p  SSH password (or set NET_PASS env)
  -o  Output file (also prints to STDOUT)
  -t  Timeout in seconds (default: 20)
END
}
```