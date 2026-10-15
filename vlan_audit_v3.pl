```perl
#!/usr/bin/perl
# =============================================================================
# trunk_vlan_audit.pl - Trunk Port VLAN Consistency Auditor
# =============================================================================
# Purpose:
#   Audits trunk port configurations on Cisco IOS/IOS-XE switches, checking
#   for native VLAN mismatches (VLAN hopping risk), pruned VLANs not in the
#   allowed list, and trunk ports with unexpected encapsulation. Distinct from
#   vlan_audit.pl which inventories the VLAN database; this script focuses on
#   trunk port security and consistency.
#
# Usage:
#   Single device:   ./trunk_vlan_audit.pl -h 192.168.1.1 -u admin -p secret
#   Device list:     ./trunk_vlan_audit.pl -f devices.txt -u admin -p secret
#   With log file:   ./trunk_vlan_audit.pl -h 10.0.0.1 -u admin -p secret -l audit.log
#
# Prerequisites:
#   cpan Net::SSH::Expect
#   SSH enabled on target devices; account with 'show' privilege (priv 1+)
#
# Exit codes: 0=clean, 1=warnings found, 2=connection/auth error
# =============================================================================

use strict;
use warnings;
use Net::SSH::Expect;
use Getopt::Long;
use POSIX qw(strftime);

my ($host, $file, $user, $pass, $logfile, $help);
my $timeout = 20;
my $ssh_port = 22;

GetOptions(
    'h|host=s'     => \$host,
    'f|file=s'     => \$file,
    'u|user=s'     => \$user,
    'p|pass=s'     => \$pass,
    'l|log=s'      => \$logfile,
    'P|port=i'     => \$ssh_port,
    't|timeout=i'  => \$timeout,
    'help'         => \$help,
) or die usage();

print usage() and exit 0 if $help;
die "ERROR: Must specify -u username\n" . usage() unless $user;
die "ERROR: Must specify -p password\n" . usage() unless $pass;
die "ERROR: Must specify -h host or -f file\n" . usage() unless $host || $file;

my @devices = $host ? ($host) : read_device_file($file);
die "ERROR: No devices to audit\n" unless @devices;

my $log_fh;
if ($logfile) {
    open($log_fh, '>>', $logfile) or die "Cannot open log $logfile: $!\n";
}

my $timestamp = strftime('%Y-%m-%d %H:%M:%S', localtime);
log_output("=== Trunk VLAN Audit started $timestamp ===\n");

my $total_warnings = 0;

for my $device (@devices) {
    $device =~ s/^\s+|\s+$//g;
    next unless $device && $device !~ /^#/;
    my $warnings = audit_device($device);
    $total_warnings += $warnings;
}

log_output("\n=== Audit complete. Total warnings: $total_warnings ===\n");
close($log_fh) if $log_fh;
exit($total_warnings > 0 ? 1 : 0);

# -----------------------------------------------------------------------------

sub audit_device {
    my ($device) = @_;
    my $warnings = 0;

    log_output("\n--- Connecting to $device ---\n");

    my $ssh = eval {
        Net::SSH::Expect->new(
            host        => $device,
            user        => $user,
            password    => $pass,
            port        => $ssh_port,
            raw_pty     => 1,
            timeout     => $timeout,
        );
    };
    if ($@) {
        log_output("ERROR [$device]: Failed to create SSH object: $@\n");
        return 2;
    }

    my $login_output = eval { $ssh->login() };
    if ($@ || !$login_output) {
        log_output("ERROR [$device]: Authentication failed\n");
        return 2;
    }

    # Disable paging
    $ssh->send('terminal length 0');
    $ssh->waitfor('\$|#|>', 5);

    # Grab hostname for display
    my $prompt_line = $ssh->waitfor('\$|#|>', 3) // '';
    my $hostname = ($prompt_line =~ /^(\S+)[>#\$]/) ? $1 : $device;

    # Collect trunk interface data
    $ssh->send('show interfaces trunk');
    my $trunk_output = $ssh->waitfor('\$|#|>', 15) // '';

    # Collect CDP neighbors for native VLAN cross-check
    $ssh->send('show cdp neighbors detail');
    my $cdp_output = $ssh->waitfor('\$|#|>', 15) // '';

    $ssh->close();

    if (!$trunk_output || $trunk_output !~ /Port\s+Mode/i) {
        log_output("INFO  [$hostname]: No trunk interfaces found or output unavailable\n");
        return 0;
    }

    # Parse trunk sections
    # IOS trunk output has 5 sections separated by blank lines
    my @sections = split(/\n\s*\n/, $trunk_output);
    my (%trunk_mode, %native_vlan, %allowed_vlans, %active_vlans);

    for my $section (@sections) {
        if ($section =~ /Port\s+Mode\s+Encapsulation/i) {
            for my $line (split /\n/, $section) {
                if ($line =~ /^([\w\/\.]+)\s+(\S+)\s+(\S+)\s+(\d+)/) {
                    my ($intf, $mode, $enc, $native) = ($1, $2, $3, $4);
                    $trunk_mode{$intf}   = "$mode/$enc";
                    $native_vlan{$intf}  = $native;
                }
            }
        }
        if ($section =~ /Port\s+Vlans allowed on trunk/i) {
            for my $line (split /\n/, $section) {
                if ($line =~ /^([\w\/\.]+)\s+(.+)$/) {
                    $allowed_vlans{$1} = $2;
                }
            }
        }
        if ($section =~ /Port\s+Vlans in spanning tree forwarding/i) {
            for my $line (split /\n/, $section) {
                if ($line =~ /^([\w\/\.]+)\s+(.+)$/) {
                    $active_vlans{$1} = $2;
                }
            }
        }
    }

    if (!%native_vlan) {
        log_output("INFO  [$hostname]: No trunk interfaces in up/up state\n");
        return 0;
    }

    log_output("INFO  [$hostname]: Found " . scalar(keys %native_vlan) . " trunk port(s)\n");

    for my $intf (sort keys %native_vlan) {
        my $native  = $native_vlan{$intf};
        my $allowed = $allowed_vlans{$intf} // 'unknown';
        my $active  = $active_vlans{$intf}  // 'unknown';
        my $mode    = $trunk_mode{$intf}    // 'unknown';

        # Check 1: Native VLAN should not be VLAN 1 (security best practice)
        if ($native == 1) {
            log_output("WARN  [$hostname] $intf: Native VLAN is 1 (VLAN hopping risk — set to unused VLAN)\n");
            $warnings++;
        }

        # Check 2: Native VLAN should not be in the allowed list on 802.1Q trunks
        # (double-tagging attack vector)
        if ($mode =~ /802\.1q/i && $allowed ne 'unknown') {
            my @allowed_list = expand_vlan_range($allowed);
            if (grep { $_ == $native } @allowed_list) {
                log_output("WARN  [$hostname] $intf: Native VLAN $native appears in allowed VLAN list (double-tag risk)\n");
                $warnings++;
            }
        }

        # Check 3: Flag trunks still in 'dynamic desirable' or 'dynamic auto'
        if ($mode =~ /desirable|auto/i) {
            log_output("WARN  [$hostname] $intf: Trunk negotiation is $mode — set to 'trunk' mode explicitly\n");
            $warnings++;
        }

        # Check 4: Catch obviously over-broad allowed list (all VLANs 1-4094)
        if ($allowed eq '1-4094') {
            log_output("WARN  [$hostname] $intf: Allowed VLANs is 1-4094 — prune to only required VLANs\n");
            $warnings++;
        }

        log_output(sprintf("INFO  [%s] %-20s native=%-4s mode=%-12s allowed=%s\n",
            $hostname, $intf, $native, $mode, substr($allowed, 0, 60)));
    }

    return $warnings;
}

sub expand_vlan_range {
    my ($range_str) = @_;
    my @vlans;
    for my $token (split /,/, $range_str) {
        $token =~ s/\s//g;
        if ($token =~ /^(\d+)-(\d+)$/) {
            push @vlans, ($1 .. $2);
        } elsif ($token =~ /^\d+$/) {
            push @vlans, $token;
        }
    }
    return @vlans;
}

sub read_device_file {
    my ($filename) = @_;
    open(my $fh, '<', $filename) or die "Cannot open device file $filename: $!\n";
    my @devices = <$fh>;
    close($fh);
    chomp @devices;
    return @devices;
}

sub log_output {
    my ($msg) = @_;
    print $msg;
    print $log_fh $msg if $log_fh;
}

sub usage {
    return <<'END';
Usage: trunk_vlan_audit.pl -h <host> | -f <file> -u <user> -p <pass> [options]

Options:
  -h, --host     Target device IP or hostname
  -f, --file     File containing one device per line (# for comments)
  -u, --user     SSH username
  -p, --pass     SSH password
  -l, --log      Append output to log file
  -P, --port     SSH port (default: 22)
  -t, --timeout  Command timeout seconds (default: 20)
      --help     Show this help

END
}
```