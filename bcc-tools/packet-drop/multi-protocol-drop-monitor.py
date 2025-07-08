#!/usr/bin/python2

#from bpfcc import BPF
#from bpfcc.utils import printb
from bcc import BPF
from bcc.utils import printb
import ctypes as ct
from socket import inet_ntop, AF_INET, inet_aton, htonl
from struct import pack, unpack
from time import strftime
import os
import socket
import struct
import argparse

def ip_to_hex(ip):
    return htonl(unpack("!I", inet_aton(ip))[0])

parser = argparse.ArgumentParser(description='Monitor network packets for specific IP addresses and ports')
parser.add_argument('--src', type=str, help='Source IP address to monitor (in dotted decimal notation)')
parser.add_argument('--dst', type=str, help='Destination IP address to monitor (in dotted decimal notation)')
parser.add_argument('--protocol', type=str, choices=['all', 'icmp', 'tcp', 'udp'], default='all', help='Protocol to monitor')
parser.add_argument('--src-port', type=int, help='Source port to monitor (for TCP/UDP)')
parser.add_argument('--dst-port', type=int, help='Destination port to monitor (for TCP/UDP)')
parser.add_argument('--log-file', type=str, help='Path to log file (if specified, output will be written to this file)')
args = parser.parse_args()

src_ip = args.src if args.src else "0.0.0.0"
dst_ip = args.dst if args.dst else "0.0.0.0"
src_port = args.src_port if args.src_port else 0
dst_port = args.dst_port if args.dst_port else 0

print("Monitoring source IP: {}".format(src_ip))
print("Monitoring destination IP: {}".format(dst_ip))
print("Protocol: {}".format(args.protocol))
if args.protocol in ['tcp', 'udp']:
    print("Source port: {}".format(src_port))
    print("Destination port: {}".format(dst_port))

src_ip_hex = ip_to_hex(src_ip)
dst_ip_hex = ip_to_hex(dst_ip)

# Set up log file handling
log_file = None
if args.log_file:
    try:
        log_file = open(args.log_file, 'a')
        log_file.write("=== Monitoring started at {} ===\n\n".format(strftime('%Y-%m-%d %H:%M:%S')))
    except Exception as e:
        print("Error opening log file: {}".format(e))
        print("Continuing without logging to file")
        log_file = None

# Helper function to handle output
def log_output(message):
    if log_file:
        log_file.write(message + '\n')
        log_file.flush()  # Ensure log is written immediately, not buffered
    else:
        print(message)

# Load BPF C code from file
bpf_c_file = os.path.join(os.path.dirname(__file__), "multi-protocol-drop-monitor.c")
try:
    with open(bpf_c_file, 'r') as f:
        bpf_text_template = f.read()
except Exception as e:
    print("Error reading BPF C file ({}): {}".format(bpf_c_file, e))
    exit(1)

protocol_map = {'all': 0, 'icmp': socket.IPPROTO_ICMP, 'tcp': socket.IPPROTO_TCP, 'udp': socket.IPPROTO_UDP}
protocol_num = protocol_map[args.protocol]

# Substitute placeholders in the loaded C code
bpf_text = bpf_text_template % (src_ip_hex, dst_ip_hex, src_port, dst_port, protocol_num)

# Initialize BPF
try:
    b = BPF(text=bpf_text)
except Exception as e:
    print("Error initializing BPF: {}".format(e))
    # Optionally print the formatted BPF text for debugging
    # print("Formatted BPF text:\n", bpf_text) 
    exit(1)

b.attach_kprobe(event="kfree_skb", fn_name="trace_kfree_skb")

# Process events from perf buffer
def print_kfree_drop_event(cpu, data, size):
    event = b["kfree_drops"].event(data)
    protocol_str = {socket.IPPROTO_ICMP: "ICMP", socket.IPPROTO_TCP: "TCP", socket.IPPROTO_UDP: "UDP"}.get(event.protocol, str(event.protocol))
                
    # Now print the actual stack trace
    log_output("Time: %s  PID: %-6d  Comm: %s" % (
        strftime("%Y-%m-%d %H:%M:%S"), event.pid, event.comm.decode('utf-8')))
    log_output("Source IP: %-15s  Destination IP: %-15s  Protocol: %s  IP ID: %d  VLAN: %d" % (
        inet_ntop(AF_INET, pack("I", event.saddr)),
        inet_ntop(AF_INET, pack("I", event.daddr)),
        protocol_str,
        event.ip_id,
        event.vlan_id))
    
    # Protocol specific info
    if event.protocol == socket.IPPROTO_ICMP:
        log_output("ICMP Type: %-2d  Code: %-2d" % (event.icmp_type, event.icmp_code))
    elif event.protocol in [socket.IPPROTO_TCP, socket.IPPROTO_UDP]:
        log_output("Source Port: %-5d  Destination Port: %-5d" % (event.sport, event.dport))
    
    log_output("Device: %s" % event.ifname.decode('utf-8'))
    
    # Stack trace with better filtering
    stack_id = event.kernel_stack_id
    if stack_id >= 0:
        stack_trace = []
        stack_syms = []
        try:
            stack_trace = list(b.get_table("stack_traces").walk(stack_id))
            for addr in stack_trace:
                sym = b.ksym(addr, show_offset=True)
                stack_syms.append(sym)
        except KeyError:
            log_output("  Failed to retrieve stack trace (ID: %d)" % stack_id)

        if stack_trace:
            log_output("Stack Trace:")
            for sym in stack_syms:
                log_output("  %s" % sym)

            # After displaying the kernel stack trace, add user stack trace display
            log_output("User Stack Trace:")
            user_stack_id = event.user_stack_id
            
            if user_stack_id >= 0:
                user_stack = []
                try:
                    user_stack = list(b.get_table("stack_traces").walk(user_stack_id))
                except KeyError:
                    log_output("  Failed to retrieve user stack trace (ID: %d)" % user_stack_id)
                
                if user_stack:
                    for addr in user_stack:
                        # For user-space, we use sym() instead of ksym()
                        symbol = b.sym(addr, event.pid, show_offset=True)
                        if symbol:
                            log_output("  %s" % symbol)
                        else:
                            log_output("  0x%x" % addr)
                else:
                    log_output("  No user stack frames found")
            else:
                error_code = abs(user_stack_id)
                error_msg = "Unknown error"
                if error_code == 1:
                    error_msg = "EFAULT: Bad address"
                elif error_code == 2:
                    error_msg = "ENOENT: No such entry"
                elif error_code == 12:
                    error_msg = "ENOMEM: Out of memory"
                elif error_code == 22:
                    error_msg = "EINVAL: Invalid argument"
                elif error_code == 14:
                    error_msg = "BPF_MAX_STACK_DEPTH exceeded"
                elif error_code == 16:
                    error_msg = "Resource temporarily unavailable"
                elif error_code == 524:
                    error_msg = "Uprobe not found"
                
                log_output("  Failed to capture user stack trace (Error: %s, code: %d)" % 
                    (error_msg, error_code))
    else:
        error_code = abs(event.kernel_stack_id)
        error_msg = "Unknown error"
        if error_code == 1:
            error_msg = "EFAULT: Bad address"
        elif error_code == 2:
            error_msg = "ENOENT: No such entry"
        elif error_code == 12:
            error_msg = "ENOMEM: Out of memory"
        elif error_code == 22:
            error_msg = "EINVAL: Invalid argument"
        elif error_code == 14:
            error_msg = "BPF_MAX_STACK_DEPTH exceeded"
        elif error_code == 16:
            error_msg = "Resource temporarily unavailable"
        elif error_code == 524:
            error_msg = "Uprobe not found"
        
        log_output("  Failed to capture kernel stack trace (Error: %s, code: %d)" % 
              (error_msg, error_code))

b["kfree_drops"].open_perf_buffer(print_kfree_drop_event)

log_output("Tracing... Hit Ctrl-C to end.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        if log_file:
            log_file.write("\n=== Monitoring ended at {} ===\n".format(strftime('%Y-%m-%d %H:%M:%S')))
            log_file.close()
        exit()
