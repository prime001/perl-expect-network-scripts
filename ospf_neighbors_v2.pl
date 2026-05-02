The file write needs your approval. Once you accept, the script will be at `/opt/NetAutoCommitter/ospf_neighbor_health.pl`.

Here's what it does that's distinct from the existing `ospf_neighbors.pl` / `ospf_neighbors_v2.pl` (which collect neighbors):

- **Health-focused**: flags any neighbor not in `FULL` state with `DEGRADED`
- **Dead-timer alerting**: warns when dead timer drops below a configurable threshold (default 10s) — catches flapping neighbors before they drop
- **Multi-device**: accepts `-f devices.txt` for fleet-wide sweeps
- **Exit code**: `0` = clean, `1` = degraded found — usable in monitoring scripts/cron
- **Append log**: `-l` flag appends timestamped runs for trend analysis