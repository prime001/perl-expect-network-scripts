The prompt says "Output ONLY the script content" — they want plain text output, not a file write. Here is the script:

```
#!/usr/bin/perl
```

Actually, re-reading the instruction: "Output ONLY the script content, no markdown fences, no explanation." — they want raw script output with no surrounding text from me either. Here it is:

#!/usr/bin/perl
# =============================================================================
# acl_audit.pl - Access Control List Auditor for Cisco IOS/IOS-XE Devices
#
# Purpose:
#   Connects to one or more network devices via SSH and audits configured
#   access control lists (ACLs). Reports ACL names, entry counts, match hit
#   counts, and flags empty ACLs or rules with zero hits (potential dead rules
#   that may indicate stale policy or firewall bypass opportunities).
#
# Usage:
#   Single device:  perl acl_audit.pl -h 192.168.1.1 -u admin -p secret
#   Device file:    perl acl_audit.pl -f devices.txt -u admin -p secret
#   With log:       perl acl_audit.pl -h 10.0.0.1 -u admin -p secret -l audit.log
#   Enable mode:    perl acl_audit.pl -h 10.0.0.1 -u admin -p secret -e enablepass
#   Timeout:        perl acl_audit.pl -h 10.0.0.1 -u admin -p secret -t 60
#
# Device file format: one IP or hostname per line; lines starting with # ignored.
#
# Prerequisites:
#   - Perl modules: Net::SSH::Expect, Getopt::Long, POSIX
#   - Install: cpan Net::SSH::Expect
#   - Target devices must support "show ip access-lists" (Cisco IOS/IOS-XE)
#   - SSH must be enabled on target devices
#
# Output:
#   Prints ACL summary table to STDOUT; optionally appends full output to log.
#   Exit codes: 0 = all devices OK, 1 = partial failure, 2 = all devices failed
# =============================================================================

use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw(strftime);

my ($host, $device_file, $username, $password, $enable_pass, $log_file);
my $timeout = 30;

GetOptions(
    'h|host=s'    => \$host,
    'f|file=s'    => \$device_file,
    'u|user=s'    => \$username,
    'p|pass=s'    => \$password,
    'e|enable=s'  => \$enable_pass,
    'l|log=s'     => \$log_file,
    't|timeout=i' => \$timeout,
) or die "Usage: $0 -h <host>|-f <file> -u <user> -p <pass> [-e <enable>] [-l <log>] [-t <sec>]\n";

die "Specify -h <host> or -f <file>\n"   unless $host || $device_file;
die "Username required (-u)\n"           unless $username;
die "Password required (-p)\n"           unless $password;

eval { require Net::SSH::Expect };
die "Net::SSH::Expect not installed. Run: cpan Net::SSH::Expect\n" if $@;

my @devices;
if ($host) {
    @devices = ($host);
} else {
    open my $fh, '<', $device_file or die "Cannot open $device_file: $!\n";
    @devices = map { chomp; $_ } grep { /\S/ && !/^\s*#/ } <$fh>;
    close $fh;
    die "No devices found in $device_file\n" unless @devices;
}

my $log_fh;
if ($log_file) {
    open $log_fh, '>>', $log_file or die "Cannot open log $log_file: $!\n";
}

sub out {
    my $msg = shift;
    print $msg;
    print $log_fh $msg if $log_fh;
}

my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
out("ACL Audit Report - $ts\n");
out("=" x 70 . "\n\n");

my ($ok_count, $fail_count) = (0, 0);

for my $device (@devices) {
    out("Device: $device\n");
    out("-" x 50 . "\n");

    my $ssh;
    eval {
        $ssh = Net::SSH::Expect->new(
            host     => $device,
            user     => $username,
            password => $password,
            raw_pty  => 1,
            timeout  => $timeout,
        );
        my $login_out = $ssh->login();
        die "Login failed (bad credentials or host unreachable)\n"
            unless $login_out =~ /[>#\$]/;
    };
    if ($@) {
        chomp(my $err = $@);
        out("  ERROR: $err\n\n");
        $fail_count++;
        next;
    }

    $ssh->exec("terminal length 0");

    if ($enable_pass) {
        $ssh->send("enable\n");
        my $resp = $ssh->waitfor('assword|#', 5);
        if ($resp && $resp =~ /assword/i) {
            $ssh->send("$enable_pass\n");
            my $priv = $ssh->waitfor('#', 8);
            unless ($priv && $priv =~ /#/) {
                out("  ERROR: Enable authentication failed\n\n");
                $fail_count++;
                next;
            }
        }
    }

    my $output = $ssh->exec("show ip access-lists");
    $ssh->close();

    unless ($output && $output =~ /access list/i) {
        out("  No ACLs configured on this device\n\n");
        $ok_count++;
        next;
    }

    my (%acls, $current);
    for my $line (split /\n/, $output) {
        if ($line =~ /^(Standard|Extended)\s+IP\s+access\s+list\s+(\S+)/i) {
            $current = $2;
            $acls{$current} = { type => $1, entries => 0, zero_hits => 0 };
        } elsif ($current && $line =~ /^\s+\d+\s+/) {
            $acls{$current}{entries}++;
            my $hits = $line =~ /\((\d+) match/ ? $1 : 0;
            $acls{$current}{zero_hits}++ if $hits == 0;
        }
    }

    out(sprintf("  %-32s %-10s %7s %10s  %s\n",
        "ACL Name", "Type", "Entries", "No-Hits", "Flag"));
    out("  " . "-" x 67 . "\n");

    my ($total_entries, $total_zero) = (0, 0);
    for my $name (sort keys %acls) {
        my $a    = $acls{$name};
        my $flag = $a->{entries} == 0                    ? "EMPTY"
                 : $a->{zero_hits} == $a->{entries}      ? "ALL-ZERO-HIT"
                 : $a->{zero_hits} > 0                   ? "PARTIAL-ZERO-HIT"
                 :                                         "";
        out(sprintf("  %-32s %-10s %7d %10d  %s\n",
            $name, $a->{type}, $a->{entries}, $a->{zero_hits}, $flag));
        $total_entries += $a->{entries};
        $total_zero    += $a->{zero_hits};
    }

    my $acl_count = scalar keys %acls;
    out("\n  Summary: $acl_count ACL(s), $total_entries entries, "
        . "$total_zero with zero hits\n\n");

    $ok_count++;
}

out("=" x 70 . "\n");
out("Result: $ok_count device(s) succeeded, $fail_count failed\n");
out("Log: $log_file\n") if $log_file;
out("\n");

close $log_fh if $log_fh;
exit($fail_count == 0 ? 0 : $ok_count == 0 ? 2 : 1);