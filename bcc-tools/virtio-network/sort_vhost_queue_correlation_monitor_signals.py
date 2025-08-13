#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Sort vhost_signal events by timestamp from correlation monitor log
Usage: python sort_vhost_signals.py < log_file
       cat log | python sort_vhost_signals.py
"""

import sys
import re

def parse_vhost_signals(input_stream):
    """Parse vhost_signal event blocks from input stream"""
    events = []
    current_event = []
    in_vhost_signal = False
    
    for line in input_stream:
        line = line.strip()
        
        # Check if this is a vhost_signal event start
        if line.startswith("Event: vhost_signal"):
            # Save previous event if exists
            if current_event and in_vhost_signal:
                events.append('\n'.join(current_event))
            
            # Start new event
            current_event = [line]
            in_vhost_signal = True
            
        elif in_vhost_signal:
            # Check if we hit the separator or new event
            if line.startswith("="*80) or line.startswith("Event:"):
                # End current event
                if current_event:
                    events.append('\n'.join(current_event))
                    current_event = []
                
                # If this is a new event line, start new event
                if line.startswith("Event: vhost_signal"):
                    current_event = [line]
                    in_vhost_signal = True
                else:
                    in_vhost_signal = False
            else:
                # Continue current event
                if line:  # Skip empty lines
                    current_event.append(line)
    
    # Add last event if exists
    if current_event and in_vhost_signal:
        events.append('\n'.join(current_event))
    
    return events

def extract_timestamp(event_text):
    """Extract timestamp from event text"""
    # Look for pattern: Timestamp: 606591802173769ns
    match = re.search(r'Timestamp: (\d+)ns', event_text)
    if match:
        return int(match.group(1))
    return 0

def extract_last_used_idx(event_text):
    """Extract last_used_idx from VQ State line"""
    # Look for pattern: last_used=37300
    match = re.search(r'last_used=(\d+)', event_text)
    if match:
        return int(match.group(1))
    return None

def format_time_diff(ns_diff):
    """Format time difference in human readable format"""
    if ns_diff < 1000:
        return "{}ns".format(ns_diff)
    elif ns_diff < 1000000:
        return "{:.1f}μs".format(ns_diff / 1000.0)
    elif ns_diff < 1000000000:
        return "{:.1f}ms".format(ns_diff / 1000000.0)
    else:
        return "{:.2f}s".format(ns_diff / 1000000000.0)

def main():
    print("Parsing vhost_signal events from input...")
    
    # Read and parse events
    events = parse_vhost_signals(sys.stdin)
    
    if not events:
        print("No vhost_signal events found!")
        return
    
    print("Found {} vhost_signal events".format(len(events)))
    
    # Extract timestamps and sort
    event_data = []
    for event in events:
        timestamp = extract_timestamp(event)
        last_used = extract_last_used_idx(event)
        event_data.append((timestamp, last_used, event))
    
    # Sort by timestamp
    event_data.sort(key=lambda x: x[0])
    
    print("=" * 100)
    print("VHOST_SIGNAL EVENTS SORTED BY TIMESTAMP")
    print("=" * 100)
    
    prev_timestamp = None
    prev_last_used = None
    
    for i, (timestamp, last_used, event) in enumerate(event_data):
        print("\n[Event #{:03d}]".format(i + 1))
        
        # Calculate time difference from previous event
        if prev_timestamp is not None:
            time_diff = timestamp - prev_timestamp
            print("Time diff from previous: {}".format(format_time_diff(time_diff)))
        
        # Show last_used_idx change
        if prev_last_used is not None and last_used is not None:
            idx_diff = last_used - prev_last_used
            print("last_used_idx change: {} -> {} (diff: {:+d})".format(
                prev_last_used, last_used, idx_diff))
        
        print("-" * 80)
        print(event)
        print("-" * 80)
        
        prev_timestamp = timestamp
        prev_last_used = last_used
    
    print("\n" + "=" * 100)
    print("SUMMARY")
    print("=" * 100)
    
    if len(event_data) >= 2:
        first_ts = event_data[0][0]
        last_ts = event_data[-1][0]
        total_time = last_ts - first_ts
        
        print("Total events: {}".format(len(event_data)))
        print("Time span: {}".format(format_time_diff(total_time)))
        if len(event_data) > 1:
            avg_interval = total_time // (len(event_data) - 1)
            print("Average interval: {}".format(format_time_diff(avg_interval)))
        
        # Analyze last_used_idx progression
        valid_events = [(ts, idx) for ts, idx, _ in event_data if idx is not None]
        if len(valid_events) >= 2:
            first_idx = valid_events[0][1]
            last_idx = valid_events[-1][1]
            print("last_used_idx progression: {} -> {} (total: {:+d})".format(
                first_idx, last_idx, last_idx - first_idx))
            
            # Check for any backwards movement
            backwards = []
            for i in range(1, len(valid_events)):
                if valid_events[i][1] < valid_events[i-1][1]:
                    backwards.append((i, valid_events[i-1][1], valid_events[i][1]))
            
            if backwards:
                print("WARNING: Found {} backwards movements in last_used_idx:".format(len(backwards)))
                for event_num, prev_idx, curr_idx in backwards:
                    print("  Event #{}: {} -> {} (diff: {:+d})".format(
                        event_num + 1, prev_idx, curr_idx, curr_idx - prev_idx))
            else:
                print("Good: last_used_idx always increases (no backwards movement)")

if __name__ == "__main__":
    main()