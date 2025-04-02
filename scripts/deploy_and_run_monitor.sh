#!/bin/bash

# Configuration file and script name
ZBS_CONF="/etc/zbs/zbs.conf"
LOCAL_SCRIPT="storage-perf.py"
REMOTE_USER="smartx"
REMOTE_DIR="/home/smartx/echken"
REMOTE_SCRIPT_NAME="storage-perf.py"
REMOTE_LOG_FILE="storage-drop-monitor.log"
STORAGE_INTERFACE="port-storage"

# --- Specify required BCC RPMs ---
# Update these filenames if necessary
BCC_RPM="bcc-0.21.0-1.el7.x86_64.rpm"
BCC_TOOLS_RPM="bcc-tools-0.21.0-1.el7.x86_64.rpm"
PYTHON_BCC_RPM="python-bcc-0.21.0-1.el7.noarch.rpm"
# Corresponding package names/versions for rpm -q check
BCC_PKG_VERSION="bcc-0.21.0-1.el7"
BCC_TOOLS_PKG_VERSION="bcc-tools-0.21.0-1.el7"
PYTHON_BCC_PKG_VERSION="python-bcc-0.21.0-1.el7"

# --- Helper Functions ---
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# --- Mode Detection ---
check_mode=false
if [ "$1" == "check" ] || [ "$1" == "--check" ]; then
    check_mode=true
    log "Running in CHECK mode."
else
    log "Running in DEPLOY mode."
fi

# --- Main Script ---

log "Starting script..."

# 1. Check local files existence (only needed for deploy mode)
if [ "$check_mode" != true ]; then
    log "Checking local files for DEPLOY mode..."
    if [ ! -f "$LOCAL_SCRIPT" ]; then
        log "ERROR: Local script '$LOCAL_SCRIPT' not found. Exiting."
        exit 1
    fi
    if [ ! -f "$BCC_RPM" ]; then
        log "ERROR: Local RPM '$BCC_RPM' not found. Exiting."
        exit 1
    fi
    if [ ! -f "$BCC_TOOLS_RPM" ]; then
        log "ERROR: Local RPM '$BCC_TOOLS_RPM' not found. Exiting."
        exit 1
    fi
    if [ ! -f "$PYTHON_BCC_RPM" ]; then
        log "ERROR: Local RPM '$PYTHON_BCC_RPM' not found. Exiting."
        exit 1
    fi
    log "Local script and required RPMs found."
fi

# 2. Extract Management IPs from zbs.conf
log "Reading management IPs from $ZBS_CONF..."
mgt_ips_line=$(grep -E '^\s*cluster_mgt_ips\s*=' "$ZBS_CONF")

if [ -z "$mgt_ips_line" ]; then
    log "ERROR: 'cluster_mgt_ips' line not found in $ZBS_CONF. Exiting."
    exit 1
fi

# Extract comma-separated IPs using sed
mgt_ips=$(echo "$mgt_ips_line" | sed -E 's/^\s*cluster_mgt_ips\s*=\s*//' | sed 's/\s//g') # Remove potential whitespace

if [ -z "$mgt_ips" ]; then
    log "ERROR: Could not extract any management IPs from $ZBS_CONF. Exiting."
    exit 1
fi

log "Found management IPs: $mgt_ips"

# Convert comma-separated string to array (requires Bash 4+)
IFS=',' read -r -a ip_array <<< "$mgt_ips"

# --- Loop through Management IPs ---
deploy_success_count=0
deploy_fail_count=0
check_running_count=0
check_not_running_count=0
check_error_count=0 # Count nodes where check failed (e.g., couldn't get IP or SSH failed)

for mgt_ip in "${ip_array[@]}"; do
    log "--- Processing node: $mgt_ip ---"

    if [ "$check_mode" != true ]; then
        # --- DEPLOY MODE ---
        node_failed=false # Flag for this specific node
        rpm_install_failed=false

        # 3a. Copy BCC RPMs
        log "Copying BCC RPMs to $mgt_ip:$REMOTE_DIR/ ..."
        if ! scp "$BCC_RPM" "$BCC_TOOLS_RPM" "$PYTHON_BCC_RPM" "$REMOTE_USER@$mgt_ip:$REMOTE_DIR/"; then
            log "ERROR: Failed to copy RPMs to $mgt_ip. Skipping this node."
            node_failed=true
            ((deploy_fail_count++))
            log "--- Finished processing node: $mgt_ip (DEPLOY FAIL - RPM SCP) ---"
            continue # Skip to the next IP
        fi
        log "BCC RPMs copied successfully to $mgt_ip."

        # 3b. Ensure directory, check/install RPMs remotely
        log "Connecting to $mgt_ip to ensure directory and check/install BCC RPMs..."
        ssh "$REMOTE_USER@$mgt_ip" bash -s -- \
            "$REMOTE_DIR" \
            "$BCC_RPM" "$BCC_TOOLS_RPM" "$PYTHON_BCC_RPM" \
            "$BCC_PKG_VERSION" "$BCC_TOOLS_PKG_VERSION" "$PYTHON_BCC_PKG_VERSION" << 'EOF'
            TARGET_DIR=$1
            RPM1=$2
            RPM2=$3
            RPM3=$4
            PKG_VER1=$5
            PKG_VER2=$6
            PKG_VER3=$7
            HOSTNAME=$(hostname)

            echo "[Remote DEPLOY $HOSTNAME] Ensuring directory '$TARGET_DIR' exists..."
            mkdir -p "$TARGET_DIR" && chown "$REMOTE_USER":"$REMOTE_USER" "$TARGET_DIR"
            dir_exit_status=$?
            if [ $dir_exit_status -ne 0 ]; then
                echo "[Remote DEPLOY $HOSTNAME] ERROR: Failed to create or chown directory '$TARGET_DIR'. Exit code: $dir_exit_status."
                exit 1 # Signal failure
            fi
            echo "[Remote DEPLOY $HOSTNAME] Directory checked/created."

            # Check if target RPM versions are already installed
            echo "[Remote DEPLOY $HOSTNAME] Checking if packages $PKG_VER1, $PKG_VER2, $PKG_VER3 are installed..."
            rpm -q "$PKG_VER1" "$PKG_VER2" "$PKG_VER3" > /dev/null 2>&1
            rpm_check_status=$?

            if [ $rpm_check_status -eq 0 ]; then
                echo "[Remote DEPLOY $HOSTNAME] Target BCC package versions already installed. Skipping installation."
            else
                echo "[Remote DEPLOY $HOSTNAME] Target BCC package versions not found (rpm -q exit code: $rpm_check_status). Attempting installation..."
                # Attempt to install the RPMs using sudo and force
                INSTALL_CMD="sudo rpm -ivh --force \"$TARGET_DIR/$RPM1\" \"$TARGET_DIR/$RPM2\" \"$TARGET_DIR/$RPM3\""
                echo "[Remote DEPLOY $HOSTNAME] Executing: $INSTALL_CMD"
                eval "$INSTALL_CMD"
                install_exit_status=$?
                if [ $install_exit_status -ne 0 ]; then
                    echo "[Remote DEPLOY $HOSTNAME] ERROR: RPM installation failed with exit code $install_exit_status."
                    # Clean up copied RPMs even if install failed
                    echo "[Remote DEPLOY $HOSTNAME] Cleaning up copied RPMs..."
                    #sudo rm -f "$TARGET_DIR/$RPM1" "$TARGET_DIR/$RPM2" "$TARGET_DIR/$RPM3"
                    exit 1 # Signal failure
                else
                    echo "[Remote DEPLOY $HOSTNAME] RPM installation completed successfully."
                fi
            fi

            # Clean up copied RPMs after successful check or install
            echo "[Remote DEPLOY $HOSTNAME] Cleaning up copied RPMs..."
            #sudo rm -f "$TARGET_DIR/$RPM1" "$TARGET_DIR/$RPM2" "$TARGET_DIR/$RPM3"
            echo "[Remote DEPLOY $HOSTNAME] RPM check/install step finished."
            exit 0 # Signal success for this step
EOF
        rpm_ssh_exit_status=$?
        if [ $rpm_ssh_exit_status -ne 0 ]; then
            log "ERROR: SSH command for RPM check/install failed on $mgt_ip with exit status $rpm_ssh_exit_status."
            node_failed=true
            rpm_install_failed=true # Mark RPM step as failed
            ((deploy_fail_count++))
            log "--- Finished processing node: $mgt_ip (DEPLOY FAIL - RPM Check/Install) ---"
            # Don't 'continue' here if you want the script copy/exec to proceed even if RPMs fail,
            # but it's safer to stop if RPMs couldn't be installed. Let's continue to stop here.
             continue
        fi
        log "BCC RPM check/install step completed successfully on $mgt_ip."

        # 3c. Copy storage-perf.py script (only if RPM step succeeded)
        log "Copying '$LOCAL_SCRIPT' to $REMOTE_USER@$mgt_ip:$REMOTE_DIR/"
        if ! scp "$LOCAL_SCRIPT" "$REMOTE_USER@$mgt_ip:$REMOTE_DIR/$REMOTE_SCRIPT_NAME"; then
            log "ERROR: Failed to copy script '$LOCAL_SCRIPT' to $mgt_ip. Skipping execution."
            node_failed=true
            ((deploy_fail_count++))
            log "--- Finished processing node: $mgt_ip (DEPLOY FAIL - Script SCP) ---"
            continue # Skip to the next IP
        fi
        log "Script '$LOCAL_SCRIPT' copied successfully to $mgt_ip."

        # 4. SSH into the node, find storage IP, handle existing process, and run the script
        log "Connecting to $mgt_ip to configure and run the script..."
        ssh "$REMOTE_USER@$mgt_ip" bash -s -- "$STORAGE_INTERFACE" "$REMOTE_DIR" "$REMOTE_SCRIPT_NAME" "$REMOTE_LOG_FILE" << 'EOF'
            STORAGE_IFACE=$1
            TARGET_DIR=$2
            SCRIPT_NAME=$3
            LOG_FILE=$4
            HOSTNAME=$(hostname) # Get hostname for logging

            echo "[Remote DEPLOY $HOSTNAME] Finding IP for interface '$STORAGE_IFACE'..."
            # Try /sbin/ip first, then /usr/sbin/ip, using portable grep/awk/cut
            storage_ip=$(/sbin/ip a show "$STORAGE_IFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
            if [ -z "$storage_ip" ]; then
                echo "[Remote DEPLOY $HOSTNAME] Trying fallback path /usr/sbin/ip..."
                storage_ip=$(/usr/sbin/ip a show "$STORAGE_IFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
            fi
            if [ -z "$storage_ip" ]; then
                echo "[Remote DEPLOY $HOSTNAME] ERROR: Could not find IPv4 address for interface '$STORAGE_IFACE'. Cannot start script."
                exit 1 # Exit the remote script section with deployment failure code
            fi
            echo "[Remote DEPLOY $HOSTNAME] Found storage IP: $storage_ip"

            # Navigate to the target directory
            cd "$TARGET_DIR" || { echo "[Remote DEPLOY $HOSTNAME] ERROR: Could not cd into '$TARGET_DIR'."; exit 1; }
            echo "[Remote DEPLOY $HOSTNAME] Changed directory to '$TARGET_DIR'"

            # Make script executable
            chmod +x "$SCRIPT_NAME"

            # Define the full command pattern for checking/killing specific instance
            CMD_PATTERN="./$SCRIPT_NAME --dst $storage_ip"

            # Check if the script is already running for this specific storage IP
            echo "[Remote DEPLOY $HOSTNAME] Checking for existing process matching '$CMD_PATTERN'..."
            if pgrep -f "$CMD_PATTERN" > /dev/null; then
                 echo "[Remote DEPLOY $HOSTNAME] Existing process(es) found matching '$CMD_PATTERN'."
                 # Rename existing log file
                 if [ -f "$LOG_FILE" ]; then
                     current_date=$(date '+%Y-%m-%d_%H-%M-%S')
                     backup_log_file="${LOG_FILE}.${current_date}"
                     echo "[Remote DEPLOY $HOSTNAME] Backing up existing log file '$LOG_FILE' to '$backup_log_file'"
                     sudo mv "$LOG_FILE" "$backup_log_file"
                 fi
                 # Kill existing process(es) using sudo
                 echo "[Remote DEPLOY $HOSTNAME] Attempting to kill existing process(es) with: sudo pkill -f \"$CMD_PATTERN\""
                 sudo pkill -f "$CMD_PATTERN"
                 kill_exit_status=$?
                 sleep 2 # Give time for the process(es) to terminate
                 if pgrep -f "$CMD_PATTERN" > /dev/null; then
                     echo "[Remote DEPLOY $HOSTNAME] WARNING: Failed to kill all existing process(es) matching '$CMD_PATTERN'."
                 else
                     echo "[Remote DEPLOY $HOSTNAME] Existing process(es) matching '$CMD_PATTERN' terminated (pkill exit status: $kill_exit_status)."
                 fi
            else
                 echo "[Remote DEPLOY $HOSTNAME] No existing process found matching '$CMD_PATTERN'."
            fi

            # Start the new process using sudo
            echo "[Remote DEPLOY $HOSTNAME] Starting script with sudo: nohup sudo ./$SCRIPT_NAME --dst $storage_ip --log-file $LOG_FILE > /dev/null 2>&1 &"
            nohup sudo ./"$SCRIPT_NAME" --dst "$storage_ip" --log-file "$LOG_FILE" > /dev/null 2>&1 &

            # Check if nohup command succeeded and if the process is running
            sleep 2 # Increased sleep duration slightly
            echo "[Remote DEPLOY $HOSTNAME] Verifying if process started matching '$CMD_PATTERN'..."
            if pgrep -f "$CMD_PATTERN" > /dev/null; then
                pids=$(pgrep -f "$CMD_PATTERN" | paste -sd,)
                echo "[Remote DEPLOY $HOSTNAME] Script seems to have started successfully in the background (Matching PIDs: $pids)."
                exit 0 # Explicitly exit with deployment success
            else
                echo "[Remote DEPLOY $HOSTNAME] ERROR: Failed to verify that the script started successfully matching '$CMD_PATTERN'."
                exit 1 # Exit with deployment failure
            fi
EOF
        ssh_exec_status=$?
        if [ $ssh_exec_status -ne 0 ]; then
            log "ERROR: SSH command sequence for script execution failed on $mgt_ip with exit status $ssh_exec_status."
            node_failed=true # Already marked if prior steps failed
            # Only increment fail count if it wasn't already incremented by prior steps
            if [ "$rpm_install_failed" != true ]; then
                 ((deploy_fail_count++))
            fi
            log "--- Finished processing node: $mgt_ip (DEPLOY FAIL - Script Exec) ---"
        elif [ "$node_failed" == false ]; then # Only log success if ALL steps for the node succeeded
             log "Remote execution commands completed successfully on $mgt_ip."
             ((deploy_success_count++))
             log "--- Finished processing node: $mgt_ip (DEPLOY SUCCESS) ---"
        # else: node already marked as failed in a previous step, counter incremented there.
        fi

    else
        # --- CHECK MODE ---
        log "Checking status on $mgt_ip..."
        # Execute commands remotely to check status
        ssh "$REMOTE_USER@$mgt_ip" bash -s -- "$STORAGE_INTERFACE" "$REMOTE_DIR" "$REMOTE_SCRIPT_NAME" << 'EOF'
            STORAGE_IFACE=$1
            TARGET_DIR=$2
            SCRIPT_NAME=$3
            HOSTNAME=$(hostname)

            echo "[Remote CHECK $HOSTNAME] Finding IP for interface '$STORAGE_IFACE'..."
            # Try /sbin/ip first, then /usr/sbin/ip, using portable grep/awk/cut
            storage_ip=$(/sbin/ip a show "$STORAGE_IFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
            if [ -z "$storage_ip" ]; then
                echo "[Remote CHECK $HOSTNAME] Trying fallback path /usr/sbin/ip..."
                storage_ip=$(/usr/sbin/ip a show "$STORAGE_IFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
            fi

            if [ -z "$storage_ip" ]; then
                echo "[Remote CHECK $HOSTNAME] ERROR: Could not find IPv4 address for interface '$STORAGE_IFACE'."
                exit 2 # Exit code 2 for check error (e.g., IP not found)
            fi
            echo "[Remote CHECK $HOSTNAME] Found storage IP: $storage_ip"

            # Navigate to the target directory to ensure relative paths in pattern work
            cd "$TARGET_DIR" || { echo "[Remote CHECK $HOSTNAME] ERROR: Could not cd into '$TARGET_DIR'."; exit 2; } # Also check error

            # Define the full command pattern for checking specific instance
            CMD_PATTERN="./$SCRIPT_NAME --dst $storage_ip"

            echo "[Remote CHECK $HOSTNAME] Checking for process matching '$CMD_PATTERN'..."
            if pgrep -f "$CMD_PATTERN" > /dev/null; then
                pids=$(pgrep -f "$CMD_PATTERN" | paste -sd,)
                echo "[Remote CHECK $HOSTNAME] Process FOUND (PIDs: $pids)."
                exit 0 # Exit code 0 for check success (process running)
            else
                echo "[Remote CHECK $HOSTNAME] Process NOT FOUND for '$CMD_PATTERN'."
                exit 1 # Exit code 1 for check "not running"
            fi
EOF
        ssh_check_status=$?
        case $ssh_check_status in
            0)
                log "Check result on $mgt_ip: PROCESS RUNNING."
                ((check_running_count++))
                ;;
            1)
                log "Check result on $mgt_ip: PROCESS NOT RUNNING."
                ((check_not_running_count++))
                ;;
            2)
                log "Check result on $mgt_ip: CHECK ERROR (Could not find IP or cd)."
                ((check_error_count++))
                ;;
            *)
                log "Check result on $mgt_ip: CHECK FAILED (SSH Error $ssh_check_status)."
                ((check_error_count++)) # Count other SSH errors as check errors
                ;;
        esac
        log "--- Finished processing node: $mgt_ip (CHECK) ---"

    fi # End of check_mode check

done

log "============================================="
if [ "$check_mode" == true ]; then
    log "Check Mode Summary:"
    log "  Nodes with monitor running: $check_running_count"
    log "  Nodes without monitor running: $check_not_running_count"
    log "  Nodes where check failed: $check_error_count"
else
    log "Deploy Mode Summary:"
    log "  Success: $deploy_success_count node(s)"
    log "  Failure: $deploy_fail_count node(s)"
fi
log "Script finished." 