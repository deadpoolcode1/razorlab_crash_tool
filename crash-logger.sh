#!/bin/bash
#
# crash-logger.sh - Kernel crash and system diagnostics logger
# For embedded Linux devices (fitlet3, i.MX8, Jetson, etc.)
#
# Features:
#   - Detects crashes from previous boot (pstore, EFI vars, journal)
#   - Logs kernel messages, system state, top processes
#   - Cyclic logging with configurable rotation
#   - Runs as systemd service
#
# Usage:
#   sudo ./crash-logger.sh          # Run in foreground
#   sudo ./crash-logger.sh daemon   # Run as background daemon
#   sudo ./crash-logger.sh check    # One-time crash check only
#   sudo ./crash-logger.sh status   # Show current status
#

set -uo pipefail

# Configuration (can be overridden via environment)
LOG_DIR="${LOG_DIR:-/var/log/crash-logger}"
MAX_LOG_SIZE_MB="${MAX_LOG_SIZE_MB:-50}"
MAX_ARCHIVES="${MAX_ARCHIVES:-10}"
LOG_INTERVAL_SEC="${LOG_INTERVAL_SEC:-60}"
LOG_FILE="${LOG_DIR}/system.log"
CRASH_REPORT_DIR="${LOG_DIR}/crash-reports"
PID_FILE="/var/run/crash-logger.pid"

# Convert MB to bytes
MAX_LOG_SIZE=$((MAX_LOG_SIZE_MB * 1024 * 1024))

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_msg() {
    echo -e "$1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_msg "${YELLOW}Warning: Running without root - some diagnostics will be limited${NC}"
        log_msg "${YELLOW}Recommend: sudo $0${NC}"
        return 1
    fi
    return 0
}

# Initialize logging directory
init_logging() {
    mkdir -p "$LOG_DIR"
    mkdir -p "$CRASH_REPORT_DIR"
    chmod 755 "$LOG_DIR"
    
    touch "$LOG_FILE"
    
    {
        echo ""
        echo "###################################################################"
        echo "### CRASH LOGGER STARTED - $(date '+%Y-%m-%d %H:%M:%S')"
        echo "###################################################################"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "Architecture: $(uname -m)"
        echo "Log rotation: ${MAX_LOG_SIZE_MB}MB, keeping ${MAX_ARCHIVES} archives"
        echo "Log interval: ${LOG_INTERVAL_SEC} seconds"
        echo ""
    } >> "$LOG_FILE"
    
    # Verify pstore for kernel panic capture
    verify_pstore
}

# Check if pstore is properly configured for kernel panic capture
verify_pstore() {
    local pstore_ok=false
    local pstore_status=""
    
    if mountpoint -q /sys/fs/pstore 2>/dev/null; then
        pstore_ok=true
        pstore_status="mounted"
        
        # Check backend type
        local backend=$(cat /sys/module/pstore/parameters/backend 2>/dev/null || \
                       dmesg 2>/dev/null | grep -oP "pstore: Registered \K\w+" | head -1 || \
                       echo "unknown")
        pstore_status="$pstore_status, backend: $backend"
    elif [[ -d /sys/fs/pstore ]]; then
        # Try to mount it
        if mount -t pstore pstore /sys/fs/pstore 2>/dev/null; then
            pstore_ok=true
            pstore_status="mounted (was unmounted)"
        else
            pstore_status="directory exists but mount failed"
        fi
    else
        pstore_status="not available"
    fi
    
    # Check journal persistence
    local journal_persistent=false
    if [[ -d /var/log/journal ]]; then
        journal_persistent=true
    fi
    
    # Log status
    {
        echo "--- CRASH CAPTURE STATUS ---"
        if $pstore_ok; then
            echo "[OK] pstore: $pstore_status"
            echo "     Kernel panics WILL be captured"
        else
            echo "[WARNING] pstore: $pstore_status"
            echo "     Kernel panics may NOT be captured!"
            echo "     Consider enabling ramoops or efi-pstore"
        fi
        
        if $journal_persistent; then
            echo "[OK] Journal: persistent (/var/log/journal exists)"
        else
            echo "[WARNING] Journal: volatile (logs lost on reboot)"
            echo "     To fix: sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald"
        fi
        echo ""
    } >> "$LOG_FILE"
    
    # Terminal output
    if $pstore_ok; then
        log_msg "${GREEN}[OK] pstore configured - kernel panics will be captured${NC}"
    else
        log_msg "${YELLOW}[WARNING] pstore not available - kernel panics may not be captured!${NC}"
    fi
    
    if ! $journal_persistent; then
        log_msg "${YELLOW}[WARNING] Journal is volatile - previous boot logs may be lost${NC}"
    fi
}

# Log a separator with timestamp
log_separator() {
    local label="$1"
    {
        echo ""
        echo "======================================================================"
        echo "=== ${label} - $(date '+%Y-%m-%d %H:%M:%S') ==="
        echo "======================================================================"
    } >> "$LOG_FILE"
}

# Check for kernel crashes from previous boot
check_previous_crashes() {
    local crash_detected=false
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local report_file="${CRASH_REPORT_DIR}/crash-report_${timestamp}.txt"
    
    log_msg "${GREEN}[*] Analyzing previous boot for crashes...${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [CRASH-CHECK] Analyzing previous boot..." >> "$LOG_FILE"
    
    {
        echo "=========================================="
        echo "       CRASH ANALYSIS REPORT"
        echo "=========================================="
        echo "Generated: $(date)"
        echo "Host: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "Boot ID: $(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo 'unknown')"
        echo "=========================================="
        echo ""
        
        # 1. Check pstore for kernel panics
        echo "--- PSTORE (Kernel Panic Storage) ---"
        if [[ -d /sys/fs/pstore ]]; then
            local pstore_files=$(find /sys/fs/pstore -type f 2>/dev/null | wc -l)
            if [[ $pstore_files -gt 0 ]]; then
                echo "*** CRASH DETECTED: Found $pstore_files pstore entries! ***"
                crash_detected=true
                for f in /sys/fs/pstore/*; do
                    if [[ -f "$f" ]]; then
                        echo ""
                        echo "--- File: $(basename $f) ---"
                        cat "$f" 2>/dev/null || echo "(unable to read)"
                    fi
                done
            else
                echo "No pstore entries in /sys/fs/pstore/"
            fi
        else
            echo "pstore not mounted"
        fi
        echo ""
        
        # 1b. Check EFI variables directly (fallback - pstore sometimes misses these)
        echo "--- EFI CRASH DUMP VARIABLES ---"
        local efi_dumps=$(ls /sys/firmware/efi/efivars/dump-type0-* 2>/dev/null | wc -l)
        if [[ $efi_dumps -gt 0 ]]; then
            echo "*** CRASH DETECTED: Found $efi_dumps EFI dump entries! ***"
            crash_detected=true
            
            # Get the timestamp from first file to show crash time
            local first_dump=$(ls /sys/firmware/efi/efivars/dump-type0-* 2>/dev/null | head -1)
            local dump_name=$(basename "$first_dump")
            # Extract timestamp from filename: dump-type0-N-1-TIMESTAMP-...
            local crash_ts=$(echo "$dump_name" | sed -n 's/dump-type0-[0-9]*-[0-9]*-\([0-9]*\)-.*/\1/p')
            if [[ -n "$crash_ts" ]]; then
                local crash_date=$(date -d "@$crash_ts" 2>/dev/null || echo "timestamp: $crash_ts")
                echo "Crash timestamp: $crash_date"
            fi
            
            echo ""
            echo "EFI dump files:"
            ls -la /sys/firmware/efi/efivars/dump-type0-* 2>/dev/null
            
            echo ""
            echo "Note: EFI variables may require efivar tool to read:"
            echo "  sudo efivar -l | grep dump"
        else
            echo "No EFI dump variables found (clean)"
        fi
        echo ""
        
        # 2. Check journal for previous boot
        echo "--- PREVIOUS BOOT JOURNAL ANALYSIS ---"
        if command -v journalctl &>/dev/null; then
            echo "Available boots:"
            journalctl --list-boots 2>/dev/null | tail -10 || echo "(unavailable)"
            echo ""
            
            # Find a previous boot that actually has data
            local found_boot=""
            local boot_age_warning=""
            
            for boot_offset in -1 -2 -3 -4 -5; do
                if journalctl --list-boots 2>/dev/null | grep -q "^ *${boot_offset} "; then
                    # Check if this boot actually has journal data
                    local line_count=$(timeout 5 journalctl -b ${boot_offset} --no-pager --lines=100 2>/dev/null | wc -l)
                    if [[ "$line_count" -gt 10 ]]; then
                        # Get boot timestamp to check age
                        local boot_info=$(journalctl --list-boots 2>/dev/null | grep "^ *${boot_offset} ")
                        local boot_date=$(echo "$boot_info" | awk '{print $3, $4}')
                        
                        # Calculate age in days (approximate)
                        local boot_epoch=$(date -d "$boot_date" +%s 2>/dev/null || echo "0")
                        local now_epoch=$(date +%s)
                        local age_days=$(( (now_epoch - boot_epoch) / 86400 ))
                        
                        if [[ $age_days -gt 7 ]]; then
                            boot_age_warning="WARNING: Boot ${boot_offset} is ${age_days} days old - journal data may have been rotated"
                        fi
                        
                        found_boot="${boot_offset}"
                        echo "Using boot ${boot_offset} (${line_count} lines, ${age_days} days ago)"
                        break
                    else
                        echo "Boot ${boot_offset}: listed but no/minimal data (rotated?)"
                    fi
                fi
            done
            
            if [[ -n "$found_boot" ]]; then
                [[ -n "$boot_age_warning" ]] && echo "$boot_age_warning"
                echo ""
                
                echo "--- Boot ${found_boot} kernel errors ---"
                local kerr=$(journalctl -b ${found_boot} -k -p err --no-pager 2>/dev/null | tail -100)
                if [[ -n "$kerr" ]]; then
                    echo "$kerr"
                else
                    echo "(no kernel errors)"
                fi
                
                echo ""
                echo "--- Boot ${found_boot} CRITICAL messages ---"
                local crit=$(journalctl -b ${found_boot} -p crit --no-pager 2>/dev/null | tail -50)
                if [[ -n "$crit" ]]; then
                    echo "$crit"
                else
                    echo "(none)"
                fi
                
                echo ""
                echo "--- Last 50 lines before shutdown (boot ${found_boot}) ---"
                journalctl -b ${found_boot} --no-pager -n 50 2>/dev/null || echo "(unavailable)"
                
                echo ""
                echo "--- Searching for crash signatures (boot ${found_boot}) ---"
                local crash_patterns="panic|oops|bug:|call trace|segfault|general protection|unable to handle|kernel BUG|watchdog|hung_task|oom-killer|out of memory"
                local panic_lines=$(journalctl -b ${found_boot} -k --no-pager 2>/dev/null | grep -ciE "$crash_patterns" || echo "0")
                if [[ "$panic_lines" -gt 0 ]]; then
                    echo "*** CRASH SIGNATURES FOUND: $panic_lines occurrences ***"
                    crash_detected=true
                    journalctl -b ${found_boot} -k --no-pager 2>/dev/null | grep -iE "$crash_patterns" | tail -80
                else
                    echo "No crash signatures found (clean)"
                fi
            else
                echo ""
                echo "No previous boot with journal data found."
                echo "Possible reasons:"
                echo "  - Journal logs were rotated (check journald.conf for retention settings)"
                echo "  - System was off for extended period"
                echo "  - Journal storage is volatile (Storage=volatile in journald.conf)"
                echo ""
                echo "To enable persistent journal:"
                echo "  sudo mkdir -p /var/log/journal"
                echo "  sudo systemctl restart systemd-journald"
            fi
        else
            echo "journalctl not available"
        fi
        echo ""
        
        # 3. Check /var/log/kern.log if exists
        echo "--- TRADITIONAL KERNEL LOGS ---"
        for klog in /var/log/kern.log.1 /var/log/syslog.1; do
            if [[ -f "$klog" ]]; then
                echo "--- $klog (last 30 lines) ---"
                tail -30 "$klog" 2>/dev/null
                echo ""
            fi
        done
        
        # 4. Boot/shutdown history
        echo "--- REBOOT/SHUTDOWN HISTORY ---"
        if command -v last &>/dev/null; then
            last -x reboot shutdown 2>/dev/null | head -15 || echo "(unavailable)"
        fi
        echo ""
        
        # 5. Kernel taint status
        echo "--- KERNEL TAINT STATUS ---"
        if [[ -f /proc/sys/kernel/tainted ]]; then
            local taint=$(cat /proc/sys/kernel/tainted)
            echo "Taint value: $taint"
            if [[ "$taint" -ne 0 ]]; then
                echo "*** Kernel is TAINTED ***"
                [[ $((taint & 1)) -ne 0 ]] && echo "  P - Proprietary module loaded"
                [[ $((taint & 2)) -ne 0 ]] && echo "  F - Module force loaded"
                [[ $((taint & 4)) -ne 0 ]] && echo "  S - SMP with non-SMP module"
                [[ $((taint & 8)) -ne 0 ]] && echo "  R - Module force unloaded"
                [[ $((taint & 16)) -ne 0 ]] && echo "  M - MCE (Machine Check Exception)"
                [[ $((taint & 32)) -ne 0 ]] && echo "  B - Bad page referenced"
                [[ $((taint & 64)) -ne 0 ]] && echo "  U - User requested taint"
                [[ $((taint & 128)) -ne 0 ]] && echo "  D - Kernel died (OOPS/BUG)"
                [[ $((taint & 512)) -ne 0 ]] && echo "  W - Kernel warning occurred"
                [[ $((taint & 4096)) -ne 0 ]] && echo "  O - Out-of-tree module loaded"
                [[ $((taint & 8192)) -ne 0 ]] && echo "  E - Unsigned module loaded"
                [[ $((taint & 16384)) -ne 0 ]] && echo "  L - Soft lockup occurred"
            else
                echo "Kernel is NOT tainted (clean)"
            fi
        fi
        echo ""
        
        # 6. MCE (Machine Check Exception)
        echo "--- MCE (Machine Check Exceptions) ---"
        dmesg 2>/dev/null | grep -iE "mce|machine check|hardware error" | tail -20 || echo "(none)"
        echo ""
        
        # 7. OOM Killer
        echo "--- OOM KILLER ACTIVITY ---"
        dmesg 2>/dev/null | grep -i "oom\|out of memory\|killed process" | tail -20 || echo "(none)"
        echo ""
        
        # Summary
        echo "=========================================="
        if $crash_detected; then
            echo "   *** CRASH INDICATORS DETECTED ***"
        else
            echo "   NO OBVIOUS CRASH INDICATORS"
        fi
        echo "=========================================="
        
    } > "$report_file"
    
    # Log summary
    if $crash_detected; then
        log_msg "${RED}[!] CRASH INDICATORS DETECTED - see $report_file${NC}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') [CRASH-CHECK] *** CRASH DETECTED *** - $report_file" >> "$LOG_FILE"
    else
        log_msg "${GREEN}[OK] No crash indicators from previous boot${NC}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') [CRASH-CHECK] Clean - no crash indicators" >> "$LOG_FILE"
    fi
    
    # Compress report
    gzip -f "$report_file" 2>/dev/null && log_msg "Report saved: ${report_file}.gz"
    
    return 0
}

# Log current dmesg
log_dmesg() {
    log_separator "DMESG (Kernel Ring Buffer)"
    if dmesg -T 2>/dev/null | tail -150 >> "$LOG_FILE"; then
        :
    elif dmesg 2>/dev/null | tail -150 >> "$LOG_FILE"; then
        :
    else
        echo "(dmesg unavailable - need root?)" >> "$LOG_FILE"
    fi
}

# Log kernel errors
log_kernel_errors() {
    log_separator "KERNEL ERRORS (Current Boot)"
    if command -v journalctl &>/dev/null; then
        local errors=$(journalctl -k -p err -b --no-pager 2>/dev/null | tail -50)
        if [[ -n "$errors" ]]; then
            echo "$errors" >> "$LOG_FILE"
        else
            echo "(no kernel errors)" >> "$LOG_FILE"
        fi
    else
        echo "(journalctl not available)" >> "$LOG_FILE"
    fi
}

# Log top processes
log_top() {
    log_separator "TOP PROCESSES"
    {
        echo "--- By CPU ---"
        ps aux --sort=-%cpu 2>/dev/null | head -15 || echo "(unavailable)"
        echo ""
        echo "--- By Memory ---"
        ps aux --sort=-%mem 2>/dev/null | head -15 || echo "(unavailable)"
    } >> "$LOG_FILE"
}

# Log memory info
log_memory() {
    log_separator "MEMORY INFO"
    {
        echo "--- free -h ---"
        free -h 2>/dev/null || echo "(unavailable)"
        echo ""
        echo "--- Key meminfo ---"
        grep -E "^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree|Dirty|AnonPages|Slab)" /proc/meminfo 2>/dev/null
        echo ""
        echo "--- vmstat ---"
        vmstat 1 2 2>/dev/null | tail -1 || echo "(unavailable)"
    } >> "$LOG_FILE"
}

# Log CPU and load
log_cpu() {
    log_separator "CPU & LOAD"
    {
        echo "Load: $(cat /proc/loadavg 2>/dev/null)"
        echo "Uptime: $(uptime 2>/dev/null)"
        echo ""
        echo "--- CPU frequencies ---"
        for cpu in /sys/devices/system/cpu/cpu[0-9]*; do
            if [[ -f "$cpu/cpufreq/scaling_cur_freq" ]]; then
                local freq=$(cat "$cpu/cpufreq/scaling_cur_freq" 2>/dev/null)
                local gov=$(cat "$cpu/cpufreq/scaling_governor" 2>/dev/null)
                echo "$(basename $cpu): $((freq/1000)) MHz ($gov)"
            fi
        done
    } >> "$LOG_FILE"
}

# Log temperatures
log_temperatures() {
    log_separator "TEMPERATURES"
    {
        echo "--- Thermal Zones ---"
        for zone in /sys/class/thermal/thermal_zone*; do
            if [[ -d "$zone" ]]; then
                local type=$(cat "$zone/type" 2>/dev/null || echo "unknown")
                local temp=$(cat "$zone/temp" 2>/dev/null || echo "0")
                echo "  $type: $((temp/1000))C"
            fi
        done
        
        echo ""
        echo "--- hwmon ---"
        for hwmon in /sys/class/hwmon/hwmon*; do
            if [[ -d "$hwmon" ]]; then
                local name=$(cat "$hwmon/name" 2>/dev/null || echo "unknown")
                for temp in "$hwmon"/temp*_input; do
                    if [[ -f "$temp" ]]; then
                        local temp_val=$(cat "$temp" 2>/dev/null)
                        local label=$(cat "${temp%_input}_label" 2>/dev/null || basename "${temp%_input}")
                        [[ -n "$temp_val" ]] && echo "  $name/$label: $((temp_val/1000))C"
                    fi
                done
            fi
        done
    } >> "$LOG_FILE"
}

# Log disk info
log_disk() {
    log_separator "DISK INFO"
    {
        echo "--- df -h ---"
        df -h 2>/dev/null | grep -v tmpfs || echo "(unavailable)"
        echo ""
        echo "--- Disk I/O (reads/writes) ---"
        cat /proc/diskstats 2>/dev/null | awk '{if($4+$8>0) print $3, "r:"$4, "w:"$8}' | grep -E "sd|nvme|mmc" | head -5
    } >> "$LOG_FILE"
}

# Log systemd status
log_systemd() {
    log_separator "SYSTEMD STATUS"
    if command -v systemctl &>/dev/null; then
        {
            echo "System: $(systemctl is-system-running 2>/dev/null)"
            echo ""
            echo "--- Failed units ---"
            systemctl --failed --no-pager --no-legend 2>/dev/null || echo "(none)"
        } >> "$LOG_FILE"
    else
        echo "(systemd not available)" >> "$LOG_FILE"
    fi
}

# Log network state
log_network() {
    log_separator "NETWORK STATE"
    {
        echo "--- Interfaces ---"
        ip -brief addr 2>/dev/null || echo "(unavailable)"
        echo ""
        echo "--- Default route ---"
        ip route 2>/dev/null | grep default
    } >> "$LOG_FILE"
}

# Rotate log if needed
rotate_log() {
    [[ ! -f "$LOG_FILE" ]] && return
    
    local file_size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo "0")
    
    if [[ "$file_size" -ge "$MAX_LOG_SIZE" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [ROTATE] Rotating log (${file_size} bytes)..." >> "$LOG_FILE"
        
        local timestamp=$(date '+%Y%m%d_%H%M%S')
        local archive="${LOG_DIR}/system_${timestamp}.log.gz"
        
        gzip -c "$LOG_FILE" > "$archive"
        > "$LOG_FILE"
        
        echo "$(date '+%Y-%m-%d %H:%M:%S') [ROTATE] New log started" >> "$LOG_FILE"
        
        cleanup_archives
        log_msg "${GREEN}[*] Log rotated: $archive${NC}"
    fi
}

# Keep only MAX_ARCHIVES compressed logs
cleanup_archives() {
    local archives=($(ls -t "${LOG_DIR}"/system_*.log.gz 2>/dev/null))
    local count=${#archives[@]}
    
    if [[ $count -gt $MAX_ARCHIVES ]]; then
        for ((i=MAX_ARCHIVES; i<count; i++)); do
            rm -f "${archives[$i]}"
            echo "$(date '+%Y-%m-%d %H:%M:%S') [CLEANUP] Deleted: ${archives[$i]}" >> "$LOG_FILE"
        done
    fi
    
    # Also cleanup crash reports
    local reports=($(ls -t "${CRASH_REPORT_DIR}"/crash-report_*.txt.gz 2>/dev/null))
    count=${#reports[@]}
    if [[ $count -gt $MAX_ARCHIVES ]]; then
        for ((i=MAX_ARCHIVES; i<count; i++)); do
            rm -f "${reports[$i]}"
        done
    fi
}

# Main logging cycle
log_cycle() {
    log_dmesg
    log_kernel_errors
    log_top
    log_memory
    log_cpu
    log_temperatures
    log_disk
    log_systemd
    log_network
    rotate_log
}

# Show status
show_status() {
    echo "Crash Logger Status"
    echo "==================="
    echo "Log directory: $LOG_DIR"
    echo ""
    
    if [[ -f "$LOG_FILE" ]]; then
        local size=$(du -h "$LOG_FILE" 2>/dev/null | cut -f1)
        echo "Current log: $LOG_FILE ($size)"
    else
        echo "Current log: (not started)"
    fi
    
    echo ""
    echo "Archives:"
    ls -lh "${LOG_DIR}"/system_*.log.gz 2>/dev/null || echo "  (none)"
    
    echo ""
    echo "Crash reports:"
    ls -lh "${CRASH_REPORT_DIR}"/crash-report_*.txt.gz 2>/dev/null || echo "  (none)"
    
    echo ""
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Daemon: running (PID $pid)"
        else
            echo "Daemon: stale PID file"
        fi
    else
        echo "Daemon: not running"
    fi
}

# Cleanup on exit
cleanup() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [EXIT] Crash logger stopping..." >> "$LOG_FILE"
    rm -f "$PID_FILE"
    exit 0
}

# Print help
print_help() {
    cat << EOF
crash-logger.sh - Kernel crash and system diagnostics logger

Usage: sudo $0 [command]

Commands:
  (none)      Run in foreground (Ctrl+C to stop)
  daemon      Run as background daemon
  check       One-time crash analysis only
  status      Show current status
  help        Show this help

Configuration (environment variables):
  LOG_DIR          Log directory (default: /var/log/crash-logger)
  MAX_LOG_SIZE_MB  Max log size before rotation (default: 50)
  MAX_ARCHIVES     Number of archives to keep (default: 10)
  LOG_INTERVAL_SEC Seconds between log cycles (default: 60)

Examples:
  sudo ./crash-logger.sh              # Run in foreground
  sudo ./crash-logger.sh daemon       # Run as daemon
  sudo ./crash-logger.sh check        # Just check for crashes
  LOG_INTERVAL_SEC=30 sudo ./crash-logger.sh  # Custom interval
EOF
}

# Main
main() {
    local mode="${1:-foreground}"
    
    case "$mode" in
        help|-h|--help)
            print_help
            ;;
        check)
            check_root
            init_logging
            check_previous_crashes
            ;;
        status)
            show_status
            ;;
        daemon)
            check_root
            init_logging
            
            echo $$ > "$PID_FILE"
            trap cleanup SIGTERM SIGINT
            
            log_msg "${GREEN}[*] Starting crash logger daemon (PID $$)${NC}"
            log_msg "    Log: $LOG_FILE"
            log_msg "    Interval: ${LOG_INTERVAL_SEC}s"
            
            check_previous_crashes
            
            while true; do
                log_cycle
                sleep "$LOG_INTERVAL_SEC"
            done
            ;;
        foreground|*)
            check_root
            init_logging
            
            trap cleanup SIGTERM SIGINT
            
            log_msg "${GREEN}[*] Starting crash logger (foreground)${NC}"
            log_msg "    Log: $LOG_FILE"
            log_msg "    Interval: ${LOG_INTERVAL_SEC}s"
            log_msg "    Press Ctrl+C to stop"
            echo ""
            
            check_previous_crashes
            
            while true; do
                log_cycle
                sleep "$LOG_INTERVAL_SEC"
            done
            ;;
    esac
}

main "$@"
