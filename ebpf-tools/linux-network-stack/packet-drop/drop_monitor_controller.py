#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
Simple controller for eth_drop.py with conditional logging
Monitors network interface rx dropped packets and runs eth_drop.py only when drops increase
"""

import os
import time
import signal
import subprocess
import argparse
from datetime import datetime

class DropMonitorController:
    def __init__(self, interface, command, stop_command=None, monitor_interval=30, log_dir="./logs"):
        self.interface = interface
        self.command = command
        self.stop_command = stop_command
        self.monitor_interval = monitor_interval
        self.log_dir = log_dir
        self.use_log_files = (log_dir != "./logs")  # True if custom log directory specified
        self.previous_drops = None
        self.current_process = None
        self.current_log_file = None
        self.running = True
        
        # Create log directory if it doesn't exist
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
    
    def log_message(self, message, force_stdout=False):
        """Write message to current log file or stdout based on log_dir setting"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_line = "[{}] {}\n".format(timestamp, message)
        
        # If custom log directory is specified and we have a current log file, write to log
        if self.use_log_files and self.current_log_file and os.path.exists(self.current_log_file) and not force_stdout:
            try:
                with open(self.current_log_file, 'a') as log_file:
                    log_file.write(log_line)
                    log_file.flush()
            except Exception:
                # If we can't write to log file, fall back to stdout
                print(log_line.strip())
        else:
            # Output to stdout if no custom log directory specified or forced
            print(log_line.strip())
    
    def get_interface_stats(self):
        """Get interface statistics using ip -s link show"""
        try:
            cmd = ["ip", "-s", "link", "show", "dev", self.interface]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            
            # Parse the output to extract rx dropped count
            lines = output.decode('utf-8').strip().split('\n')
            for i, line in enumerate(lines):
                if "RX:" in line and "packets" in line:
                    # Next line should contain the actual numbers
                    if i + 1 < len(lines):
                        stats_line = lines[i + 1].strip()
                        # Format: bytes packets errors dropped overrun mcast
                        stats = stats_line.split()
                        if len(stats) >= 4:
                            return int(stats[3])  # dropped is 4th field (index 3)
            return None
        except Exception as e:
            print("Error getting interface stats: {}".format(e))
            return None
    
    def start_monitoring(self):
        """Start monitoring command and redirect output to log file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_log_file = os.path.join(self.log_dir, "monitor_{}.log".format(timestamp))
        
        # Write initial info to log file
        with open(self.current_log_file, 'w') as log_file:
            log_file.write("=== Drop Monitor Controller Log ===\n")
            log_file.write("Start time: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            log_file.write("Interface: {}\n".format(self.interface))
            log_file.write("Command: {}\n".format(self.command))
            log_file.write("="*50 + "\n\n")
            log_file.flush()
        
        try:
            with open(self.current_log_file, 'a') as log_file:
                # Parse command string into list for subprocess
                if isinstance(self.command, str):
                    import shlex
                    cmd = shlex.split(self.command)
                else:
                    cmd = self.command
                
                self.current_process = subprocess.Popen(
                    cmd,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    preexec_fn=os.setsid  # Create new process group
                )
        except Exception as e:
            self.log_message("Error starting monitoring command: {}".format(e))
            self.current_process = None
    
    def stop_monitoring(self):
        """Stop monitoring process - must be called at end of each cycle"""
        if self.current_process:
            if self.stop_command:
                # Use custom stop command
                try:
                    self.log_message("Executing stop command: {}".format(self.stop_command))
                    
                    # Parse stop command
                    if isinstance(self.stop_command, str):
                        import shlex
                        stop_cmd = shlex.split(self.stop_command)
                    else:
                        stop_cmd = self.stop_command
                    
                    # Execute stop command
                    result = subprocess.run(stop_cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode != 0:
                        self.log_message("Warning: Stop command failed with code {}: {}".format(
                            result.returncode, result.stderr.strip()))
                    else:
                        self.log_message("Stop command executed successfully")
                        
                except Exception as e:
                    self.log_message("Warning: Error executing stop command: {}".format(e))
                
                # Still try to clean up the process we started
                try:
                    if self.current_process.poll() is None:  # Process still running
                        self.current_process.terminate()
                        self.current_process.wait(timeout=2)
                except Exception:
                    pass
            else:
                # Use original method
                try:
                    # Kill the entire process group to ensure cleanup
                    os.killpg(os.getpgid(self.current_process.pid), signal.SIGTERM)
                    self.current_process.wait(timeout=5)
                except Exception as e:
                    self.log_message("Warning: Error stopping monitoring command: {}".format(e))
                    try:
                        # Force kill if graceful termination failed
                        os.killpg(os.getpgid(self.current_process.pid), signal.SIGKILL)
                        self.current_process.wait(timeout=2)
                    except Exception:
                        pass
            
            self.current_process = None
            self.log_message("Stopped monitoring command")
    
    def cleanup_log_file(self):
        """Remove current log file if no drops were detected"""
        if self.current_log_file and os.path.exists(self.current_log_file):
            log_file_name = self.current_log_file
            try:
                os.remove(self.current_log_file)
                # Only output to stdout if no custom log directory
                if not self.use_log_files:
                    print("[{}] Removed log file (no drops detected): {}".format(
                        datetime.now().strftime("%H:%M:%S"), log_file_name))
            except Exception as e:
                if not self.use_log_files:
                    print("Warning: Could not remove log file {}: {}".format(self.current_log_file, e))
        self.current_log_file = None
    
    def signal_handler(self, signum, _):
        """Handle Ctrl+C gracefully"""
        print("\n[{}] Received signal {}, shutting down...".format(
            datetime.now().strftime("%H:%M:%S"), signum))
        self.running = False
        if self.current_process:
            self.stop_monitoring()
    
    def run(self):
        """Main monitoring loop"""
        print("Drop Monitor Controller")
        print("Interface: {}".format(self.interface))
        print("Command: {}".format(self.command))
        if self.stop_command:
            print("Stop command: {}".format(self.stop_command))
        else:
            print("Stop method: Process group termination")
        print("Monitor interval: {} seconds".format(self.monitor_interval))
        print("Log directory: {}".format(self.log_dir))
        print("-" * 60)
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            while self.running:
                # Get current interface stats
                current_drops = self.get_interface_stats()
                
                if current_drops is None:
                    if not self.use_log_files:
                        print("[{}] Failed to get interface stats".format(datetime.now().strftime("%H:%M:%S")))
                    time.sleep(self.monitor_interval)
                    continue
                
                if self.previous_drops is None:
                    # First run - just record the baseline
                    self.previous_drops = current_drops
                    if not self.use_log_files:
                        print("[{}] Interface {} rx dropped: {} (baseline)".format(
                            datetime.now().strftime("%H:%M:%S"), self.interface, current_drops))
                else:
                    # Check for drop increment
                    drop_increment = current_drops - self.previous_drops
                    
                    if drop_increment > 0:
                        # Start monitoring for this cycle
                        self.start_monitoring()
                        
                        # Add drop increment info to log
                        self.log_message("Interface {} rx dropped: {} -> {} (+{}) - Drop increment detected".format(
                            self.interface, self.previous_drops, current_drops, drop_increment))
                        
                        # Wait for the monitoring period, then stop
                        time.sleep(self.monitor_interval)
                        self.stop_monitoring()
                        
                        # Keep the log since drops were detected
                        if not self.use_log_files:
                            print("[{}] Kept log file (drops detected): {}".format(
                                datetime.now().strftime("%H:%M:%S"), self.current_log_file))
                        self.current_log_file = None
                    else:
                        # Start monitoring for this cycle anyway to capture baseline
                        self.start_monitoring()
                        
                        # Add no change info to log
                        self.log_message("Interface {} rx dropped: {} (no change, increment: {})".format(
                            self.interface, current_drops, drop_increment))
                        
                        # Wait for the monitoring period, then stop
                        time.sleep(self.monitor_interval)
                        self.stop_monitoring()
                        
                        # Remove log since no drops were detected
                        self.cleanup_log_file()
                    
                    # Update previous drops count
                    self.previous_drops = current_drops
                
                # No additional sleep needed since we waited during monitoring
                
        except Exception as e:
            print("Error in main loop: {}".format(e))
        finally:
            if self.current_process:
                self.stop_monitoring()

def main():
    parser = argparse.ArgumentParser(description='Monitor interface drops and control monitoring command')
    parser.add_argument('--interface', required=True, help='Network interface to monitor')
    parser.add_argument('--command', required=True, help='Command to run for monitoring (e.g., "sudo python2 eth_drop.py --interface port-mgt")')
    parser.add_argument('--stop-command', help='Command to stop monitoring processes (e.g., "sudo pkill -f eth_drop.py")')
    parser.add_argument('--interval', type=int, default=30, help='Monitoring interval in seconds')
    parser.add_argument('--log-dir', default='./logs', help='Directory for log files')
    
    args = parser.parse_args()
    
    controller = DropMonitorController(
        interface=args.interface,
        command=args.command,
        stop_command=args.stop_command,
        monitor_interval=args.interval,
        log_dir=args.log_dir
    )
    
    controller.run()

if __name__ == '__main__':
    main()