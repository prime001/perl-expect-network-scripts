The write was blocked pending your approval. Once you approve, the script will be saved to `/opt/NetAutoCommitter/hardware_health.pl`.

The script is a **hardware health monitor** (`hardware_health.pl`) — distinct from all existing scripts in the repo. It:

- Checks **CPU utilization** (5s/1min/5min averages, warns above 80%)
- Checks **memory** (processor pool used/free/%, warns above 85%)
- Checks **environmental sensors** (temperature, fans, power — parses `show environment all` for CRITICAL/WARNING/FAIL strings)
- Reports **system uptime**
- Accepts a single host (`-h`) or device list file (`-f`), optional log file (`-l`), configurable timeout (`-t`)
- Uses `Net::SSH::Expect` with `StrictHostKeyChecking=no` for fleet automation
- Timestamps every output line and writes to both STDOUT and log file simultaneously