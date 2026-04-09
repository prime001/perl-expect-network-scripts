The script is ready. Here's what `bgp_peers_v2.pl` adds over `bgp_peers.pl`:

- **Prefix threshold alerting** (`--min-prefixes N`) — alerts when any peer drops below a minimum prefix count
- **Baseline comparison** (`--baseline FILE` / `--save-baseline FILE`) — saves prefix counts as a snapshot and alerts on `--drop-pct` percentage decline vs prior run
- **CSV output** (`--csv FILE`) — machine-readable results for trending/dashboards
- **Remote AS tracking** — parses and reports the remote AS number per peer
- **Annotated device file** — accepts optional `AS65001` annotations in the host file
- **Distinct exit codes** — 0=clean, 1=threshold violations, 2=device connection errors (useful for Nagios/monitoring integration)

Usage example for daily monitoring:
```bash
# Day 1: save baseline
perl bgp_peers_v2.pl --file routers.txt --save-baseline /var/lib/bgp_baseline.dat

# Day 2+: alert if any peer drops >15% prefixes or falls below 100
perl bgp_peers_v2.pl --file routers.txt --baseline /var/lib/bgp_baseline.dat \
    --min-prefixes 100 --drop-pct 15 --log /var/log/bgp_monitor.log --csv /tmp/bgp_report.csv
```