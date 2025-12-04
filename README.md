# Crash Logger

Kernel crash and system diagnostics logger for embedded Linux devices.

Designed for production environments where you need to understand why devices crashed after the fact - particularly useful for embedded systems like CompuLab fitlet3, NXP i.MX8, NVIDIA Jetson, and similar platforms.

## Features

- **Crash Detection**: Analyzes previous boot for kernel panics, oops, OOM kills, segfaults
- **Multiple Sources**: Checks pstore, EFI variables, journald, and traditional kernel logs
- **System Monitoring**: Periodically logs dmesg, processes, memory, CPU, temperatures, disk, network
- **Cyclic Logging**: Rotates at configurable size (default 50MB), keeps N archives (default 10)
- **Systemd Integration**: Runs as a system service, starts on boot
- **Lightweight**: Pure bash, no dependencies beyond standard Linux tools

## Quick Start

### Download and Transfer to Device

```bash
# On your PC - clone the repository
git clone https://github.com/deadpoolcode1/razorlab_crash_tool.git
cd razorlab_crash_tool

# Transfer to target device via SCP
scp -r . user@device-ip:~/crash-logger/

# SSH into the device
ssh user@device-ip
cd ~/crash-logger

# Make scripts executable
chmod 777 *.sh

# Install as system service
sudo ./install.sh
```

### Alternative: Direct Clone on Device (if internet available)

```bash
# On the target device
git clone https://github.com/deadpoolcode1/razorlab_crash_tool.git
cd razorlab_crash_tool
chmod 777 *.sh
sudo ./install.sh
```

## Installation

### As a Systemd Service (Recommended)

```bash
# Make sure scripts are executable first!
chmod 777 *.sh

# Install
sudo ./install.sh
```

This will:
1. Copy `crash-logger.sh` to `/usr/local/bin/`
2. Install systemd service
3. Enable and start the service

### Verify Installation

```bash
# Check service is running
systemctl status crash-logger

# Check for crashes
sudo /usr/local/bin/crash-logger.sh check
```

### Manual Run (for testing)

```bash
# Make executable
chmod 777 crash-logger.sh

# Run in foreground (Ctrl+C to stop)
sudo ./crash-logger.sh

# Just check for crashes from previous boot
sudo ./crash-logger.sh check

# Check status
sudo ./crash-logger.sh status
```

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `crash-logger.sh` | Run in foreground |
| `crash-logger.sh daemon` | Run as background daemon |
| `crash-logger.sh check` | One-time crash analysis |
| `crash-logger.sh status` | Show log status |
| `crash-logger.sh help` | Show help |

### Service Management

```bash
systemctl status crash-logger     # Check status
systemctl stop crash-logger       # Stop
systemctl start crash-logger      # Start
systemctl restart crash-logger    # Restart
journalctl -u crash-logger -f     # Follow service logs
```



## Configuration

Environment variables (set in `/etc/systemd/system/crash-logger.service` or shell):

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_DIR` | `/var/log/crash-logger` | Log directory |
| `MAX_LOG_SIZE_MB` | `50` | Max log size before rotation |
| `MAX_ARCHIVES` | `10` | Number of archives to keep |
| `LOG_INTERVAL_SEC` | `60` | Seconds between log cycles |

### Customizing Service

Edit the service file:
```bash
sudo systemctl edit crash-logger
```

Or modify `/etc/systemd/system/crash-logger.service` directly, then:
```bash
sudo systemctl daemon-reload
sudo systemctl restart crash-logger
```

## Log Structure

```
/var/log/crash-logger/
├── system.log                          # Current log file
├── system_YYYYMMDD_HHMMSS.log.gz       # Rotated archives
└── crash-reports/
    └── crash-report_YYYYMMDD_HHMMSS.txt.gz  # Crash analysis reports
```

## What Gets Logged

### Periodic System State (every 60s by default)

- **Kernel messages** (dmesg) - last 150 lines
- **Kernel errors** from journalctl
- **Top processes** by CPU and memory
- **Memory info** - free, meminfo, vmstat
- **CPU & Load** - load average, frequencies
- **Temperatures** - thermal zones, hwmon sensors
- **Disk** - usage, I/O stats
- **Systemd** - failed units
- **Network** - interfaces, routes

### Crash Analysis (on startup / manual check)

- **pstore entries** - kernel panic storage (ramoops, efi-pstore)
- **EFI variables** - crash dumps in firmware
- **Previous boot journal** - kernel errors, crash signatures
- **Traditional logs** - kern.log, syslog
- **Reboot history** - via `last` command
- **Kernel taint** - indicates problems occurred
- **OOM kills** - out of memory killer activity
- **MCE** - machine check exceptions

## Crash Detection Patterns

The tool searches for these patterns in kernel logs:
- `panic`
- `oops`
- `bug:`
- `call trace`
- `segfault`
- `general protection`
- `unable to handle`
- `kernel BUG`
- `watchdog`
- `hung_task`
- `oom-killer`
- `out of memory`

## Analyzing Crashes

After a device crashes and reboots:

```bash
# Run crash analysis
sudo /usr/local/bin/crash-logger.sh check

# View the crash report
ls /var/log/crash-logger/crash-reports/
zcat /var/log/crash-logger/crash-reports/crash-report_*.txt.gz | less

# Search for specific issues
zgrep -i "panic\|oops\|oom" /var/log/crash-logger/system_*.log.gz

# View around crash time
zcat /var/log/crash-logger/system_*.log.gz | less
```

## Troubleshooting

### "Permission denied" when running scripts
```bash
chmod 777 *.sh
```

### Service won't start
```bash
journalctl -u crash-logger -n 50
```

### No crash data captured
- Check pstore is mounted: `mount | grep pstore`
- Check journal persistence: `ls /var/log/journal`
- Ensure running as root

### Enable persistent journal
```bash
sudo mkdir -p /var/log/journal
sudo systemctl restart systemd-journald
```

## Uninstall

```bash
sudo ./uninstall.sh
```

Logs are preserved in `/var/log/crash-logger/`. To remove:
```bash
sudo rm -rf /var/log/crash-logger
```

## Requirements

- Root access for full diagnostics
- ~500MB disk space for logs (configurable)



## Files

```
razorlab_crash_tool/
├── .gitignore              # Git ignore patterns
├── LICENSE                 # MIT License
├── README.md               # This file
├── crash-logger.sh         # Main script
├── crash-logger.service    # Systemd unit file
├── install.sh              # Installer
└── uninstall.sh            # Uninstaller
```
