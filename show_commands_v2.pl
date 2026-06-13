```perl
#!/usr/bin/perl
use strict;
use warnings;
use Expect;
use Getopt::Long;
use POSIX qw(strftime);

# cdp_lldp_neighbors.pl - Cisco CDP/LLDP Neighbor Discovery
#
# PURPOSE:
#   Connects to one or more network devices via SSH and collects CDP and LLDP
#   neighbor tables. Useful for topology mapping, change verification, and
#   documenting physical adjacencies before/after maintenance windows.
#
# USAGE:
#   Single device:   ./cdp_lldp_neighbors.pl -h 192.168.1.1 -u admin -p secret
#   Device file:     ./cdp_lldp_neighbors.pl -f devices.txt -u admin -p secret
#   With log file:   ./cdp_lldp_neighbors.pl -h 10.0.0.1 -u admin -p secret -l neighbors.log
#   LLDP only:       ./cdp_lldp_neighbors.pl -h 10.0.0.1 -u admin -p secret --lldp-only
#
# PREREQUISITES:
#   cpan install Expect
#   SSH key auth or password auth; device must have CDP/LLDP enabled
#   Tested against IOS 15.x, IOS-XE 16.x/17.x
#
# DEVICE FILE FORMAT: one IP or hostname per line, lines starting with # ignored

my ($host, $user, $pass, $enable_pass, $device_file, $log_file);
my ($lldp_only, $cdp_only, $timeout) = (0, 0, 15);

GetOptions(
    'h|host=s'       => \$host,
    'u|user=s'       => \$user,
    'p|pass=s'       => \$pass,
    'e|enable=s'     => \$enable_pass,
    'f|file=s'       => \$device_file,
    'l|log=s'        => \$log_file,
    'lldp-only'      => \$lldp_only,
    'cdp-only'       => \$cdp_only,
    't|timeout=i'    => \$timeout,
) or die "Usage: $0 -h HOST | -f FILE -u USER -p PASS [-e ENABLE] [-l LOGFILE] [--lldp-only|--cdp-only]\n";

die "Specify -h HOST or -f FILE\n" unless $host || $device_file;
die "Username (-u) required\n" unless $user;
die "Password (-p) required\n" unless $pass;

my @devices;
if ($device_file) {
    open(my $fh, '<', $device_file) or die "Cannot open $device_file: $!\n";
    while (<$fh>) { chomp; next if /^\s*#/ || /^\s*$/; push @devices, $_; }
    close $fh;
} else {
    @devices = ($host);
}

my $log_fh;
if ($log_file) {
    open($log_fh, '>', $log_file) or die "Cannot open log $log_file: $!\n";
}

sub log_output {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub collect_neighbors {
    my ($device) = @_;
    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);

    log_output("\n" . "=" x 60 . "\n");
    log_output("Device: $device  [$timestamp]\n");
    log_output("=" x 60 . "\n");

    my $exp = Expect->new();
    $exp->raw_pty(1);
    $exp->log_stdout(0);

    unless ($exp->spawn("ssh -o StrictHostKeyChecking=no -o ConnectTimeout=$timeout $user\@$device")) {
        log_output("ERROR: Failed to spawn SSH to $device: $!\n");
        return;
    }

    my $logged_in = 0;
    $exp->expect($timeout,
        [ qr/[Pp]assword:/,        sub { $exp->send("$pass\n"); exp_continue; } ],
        [ qr/yes\/no/,             sub { $exp->send("yes\n");   exp_continue; } ],
        [ qr/Connection refused/,  sub { log_output("ERROR: Connection refused on $device\n"); } ],
        [ qr/No route to host/,    sub { log_output("ERROR: No route to $device\n"); } ],
        [ qr/[>#]\s*$/,            sub { $logged_in = 1; } ],
        [ timeout => sub { log_output("ERROR: Timeout connecting to $device\n"); } ],
    );

    unless ($logged_in) { $exp->soft_close(); return; }

    # Enter enable mode if needed
    my $prompt = ($exp->before() =~ />/) ? 'user' : 'priv';
    if ($prompt eq 'user') {
        $exp->send("enable\n");
        $exp->expect($timeout,
            [ qr/[Pp]assword:/,  sub { $exp->send(($enable_pass // $pass) . "\n"); exp_continue; } ],
            [ qr/#\s*$/,         sub { } ],
            [ timeout =>         sub { log_output("WARN: Could not enter enable mode on $device\n"); } ],
        );
    }

    $exp->send("terminal length 0\n");
    $exp->expect($timeout, [ qr/#\s*$/, sub { } ]);

    my @commands;
    push @commands, 'show cdp neighbors detail' unless $lldp_only;
    push @commands, 'show lldp neighbors detail' unless $cdp_only;

    for my $cmd (@commands) {
        $exp->send("$cmd\n");
        my $output = '';
        $exp->expect(30,
            [ qr/#\s*$/m, sub {
                $output = $exp->before();
                $output =~ s/\r//g;
            }],
            [ timeout => sub { log_output("WARN: Timeout on '$cmd' for $device\n"); } ],
        );
        if ($output) {
            log_output("\n--- $cmd ---\n");
            # Strip the echoed command line
            $output =~ s/^[^\n]*\n//;
            log_output($output . "\n");
        }
    }

    $exp->send("exit\n");
    $exp->soft_close();
}

for my $dev (@devices) {
    collect_neighbors($dev);
}

close $log_fh if $log_fh;
log_output("\nDone. Processed " . scalar(@devices) . " device(s).\n");
log_output("Output saved to $log_file\n") if $log_file;
```