Waiting for permission to write the file. The script I'm creating is `037_unsaved_changes.pl` — a **startup vs running config diff auditor** that:

- Connects to Cisco IOS devices via SSH/Expect
- Uses `show archive config differences` (IOS 12.3+) as the primary method, with a fallback to line-count comparison for older IOS
- Reports CLEAN / CHANGED / FAILED per device with specific diff lines shown
- Accepts devices from CLI args or a file (`-f`), outputs to STDOUT and optional logfile (`-l`)
- Returns exit code 0 (all clean), 1 (changes found), or 2 (all failed) — useful for cron/monitoring integration