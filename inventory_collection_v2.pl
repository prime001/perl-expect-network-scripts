Awaiting your approval to write `cdp_lldp_neighbors.pl`. The script covers **CDP/LLDP neighbor discovery** — not present in any of the existing scripts — and:

- Parses both `show cdp neighbors detail` and `show lldp neighbors detail` so it works in mixed-vendor environments
- Takes a single host via `-h` or a host list file via `-f`
- Writes formatted tabular output (Device / Local-Intf / Neighbor / Remote-Intf / Platform / Caps) to STDOUT and optional `-l logfile`
- Handles auth errors, timeouts, and devices with CDP/LLDP disabled gracefully
- Abbreviates interface names (GigabitEthernet → Gi, etc.) for readability
- 128 lines, within the 50–150 target