Looking at your existing repo, I see you have good coverage of configuration (VLAN, interface, BGP, OSPF) and operational tasks (NTP, backup, log parsing). Before I design the script, I need to understand what task would be most valuable for your portfolio.

**What specific network operation should this script automate?**

Here are some gaps I notice:
- **Device health monitoring** — CPU, memory, uptime, temperature (practical for NOC dashboards)
- **Routing table verification** — check for specific routes, BGP route flapping, lost routes
- **Interface error statistics** — collect/alert on errors, discards, collisions across devices
- **Access list audits** — identify unused ACLs, track rule hit counts
- **DNS/NTP server reachability** — validate infrastructure dependencies
- **Device reachability & baseline health** — multi-device connectivity check with timeout handling

Which of these would add the most value to your portfolio, or do you have something else in mind? Pick one and I'll design it properly.