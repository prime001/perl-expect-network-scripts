```perl
#!/usr/bin/perl
#==============================================================================
# acl_audit.pl - Cisco IOS/IOS-XE Access Control List Security Auditor
#
# PURPOSE:
#   Audits IP access-lists on Cisco devices via SSH. Reports per-ACL rule
#   counts, flags ACLs where every rule has zero hits (candidates for removal),
#   and warns on permit-ip-any-any entries that may represent security gaps.
#   Designed for quarterly security reviews and firewall cleanup campaigns.
#
# USAGE:
#   Single device:  ./acl_audit.pl -h 192.168.1.1 -u admin -p secret
#   Device list:    ./acl_audit.pl -f devices.txt  -u admin -p secret -l audit.log
#
# PREREQUISITES:
#   perl -MCPAN -e 'install Net::SSH::Expect'
#   Target devices must permit SSH and 'show ip access-lists' at exec level
#
# OUTPUT FLAGS:
#   [UNUSED?] = every rule in the ACL has zero hit count (review for removal)
#   [RISKY]   = ACL contains one or more 'permit ip any any' entries
#==============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $logfile);
GetOptions(
    'h|host=s' => \$host,
    'f|file=s' => \$file,
    'u|user=s' => \$user,
    'p|pass=s' => \$pass,
    'l|log=s'  => \$logfile,
) or die "Usage: $0 -h HOST|-f FILE -u USER -p PASS [-l LOGFILE]\n";

die "Specify -h HOST or -f FILE\n" unless $host || $file;
die "Specify -u USER\n"            unless $user;
die "Specify -p PASS\n"            unless $pass;

my @devices;
if ($host) {
    @devices = ($host);
} else {
    open my $fh, '<', $file or die "Cannot open device list '$file': $!\n";
    @devices = grep { /\S/ && !/^\s*#/ } map { chomp; $_ } <$fh>;
    close $fh;
}
die "No devices to process\n" unless @devices;

my $LOG;
if ($logfile) {
    open $LOG, '>>', $logfile or die "Cannot open log '$logfile': $!\n";
    printf $LOG "# acl_audit.pl started %s\n", strftime('%Y-%m-%d %H:%M:%S', localtime);
}

sub emit {
    print @_;
    print $LOG @_ if $LOG;
}

sub audit_device {
    my ($device) = @_;
    my $stamp = strftime('%Y-%m-%d %H:%M:%S', localtime);

    emit("\n" . "=" x 64 . "\n");
    emit(sprintf "Device: %-20s  Timestamp: %s\n", $device, $stamp);
    emit("=" x 64 . "\n");

    my $ssh = Net::SSH::Expect->new(
        host     => $device,
        user     => $user,
        password => $pass,
        raw_pty  => 1,
        timeout  => 20,
    );

    eval { $ssh->login() };
    if ($@) {
        emit("  ERROR: SSH login failed ($device): $@\n");
        return;
    }

    $ssh->send("terminal length 0");
    $ssh->waitfor('#\s*$', 5);

    $ssh->send("show ip access-lists");
    my $output = $ssh->waitfor('#\s*$', 30);

    $ssh->send("exit");
    $ssh->close();

    unless ($output && $output =~ /access\s+list/i) {
        emit("  No IP access-lists found on this device.\n");
        return;
    }

    my (%acls, $current);
    for my $line (split /\n/, $output) {
        if ($line =~ /^(?:Standard|Extended)\s+IP\s+access\s+list\s+(\S+)/i) {
            $current = $1;
            $acls{$current} = { total => 0, zerohit => 0, permit_any => 0 };
        } elsif ($current && $line =~ /^\s+\d+\s+/) {
            $acls{$current}{total}++;
            my $hits = ($line =~ /\((\d+)\s+match/) ? $1 : 0;
            $acls{$current}{zerohit}++    if $hits == 0;
            $acls{$current}{permit_any}++ if $line =~ /permit\s+ip\s+any\s+any/i;
        }
    }

    if (!%acls) {
        emit("  Unable to parse access-list output.\n");
        return;
    }

    emit(sprintf "  %-34s %6s %9s %11s  Flags\n", "ACL Name", "Rules", "ZeroHit", "PermitAny");
    emit("  " . "-" x 64 . "\n");

    my ($unused_count, $risky_count) = (0, 0);
    for my $name (sort keys %acls) {
        my $a = $acls{$name};
        my @flags;
        if ($a->{total} > 0 && $a->{zerohit} == $a->{total}) {
            push @flags, '[UNUSED?]';
            $unused_count++;
        }
        if ($a->{permit_any} > 0) {
            push @flags, '[RISKY]';
            $risky_count++;
        }
        emit(sprintf "  %-34s %6d %9d %11d  %s\n",
            $name, $a->{total}, $a->{zerohit}, $a->{permit_any}, join(' ', @flags));
    }

    emit(sprintf "\n  SUMMARY: %d ACL(s) | %d possibly unused | %d with permit-any\n",
        scalar keys %acls, $unused_count, $risky_count);
}

audit_device($_) for @devices;

my $done = strftime('%Y-%m-%d %H:%M:%S', localtime);
emit("\n# Audit complete $done\n");
close $LOG if $LOG;
```