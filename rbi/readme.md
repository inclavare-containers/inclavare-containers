# Reproducible Build Infrastructure
For convenience, some scripts are collected for automatically building.
## Files
*   `rbi.sh` main script. Use `./rbi.sh help` to see details.
*   `kata-agent/` scripts related to RB of kata-agent.

## Instructions
### RB for kata-agent
Firstly, build RBCI(Reproducible Build Container Image) for kata-agent
```bash
./rbi.sh agent-image
```
Check the reproducibility of source code in `/path/to/kata-containers`.
```
./rbi.sh agent-local /path/to/kata-containers
```
Or, check the reproducibility of source code from github.com.
```bash
./rbi.sh agent-git
```
Above 2 operations can both produce a report and an artifest in `report/`.

Delete RBCI for kata-agent
```bash
./rbi.sh agent-image
```

Clean all tempfiles
```bash
./rbi clean
```