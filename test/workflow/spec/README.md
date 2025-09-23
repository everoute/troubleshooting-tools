# Test Specification Configuration Guide

This document explains how to configure test specifications for the test case generator.

## Configuration Structure

### Basic Structure
```yaml
metadata:
  name: "Test Specification Name"
  description: "Description of the test specification"
  version: "1.0"

variables:
  # Environment-specific variables

test_matrix:
  # Test matrix definitions

defaults:
  # Global default settings
```

## Variables Section

Define environment-specific variables that will be substituted in templates:

```yaml
variables:
  system-network:
    LOCAL_IP: "10.132.114.11"
    REMOTE_IP: "10.132.114.12"
    PHY_INTERFACE: "ens11"
    INTERNAL_INTERFACE: "port-storage"

  vm-network:
    LOCAL_IP: "172.21.153.114"
    REMOTE_IP: "172.21.153.113"
    PHY_INTERFACE: "ens4"
    VM_INTERFACE: "vnet0"
```

## Test Matrix Section

### Category Configuration

Each category can have its own duration setting:

```yaml
test_matrix:
  system-network:
    duration: 3  # Category-specific duration (optional)
    tools:
      # Tool definitions
    directions:
      # Direction definitions

  vm-network:
    duration: 7  # Different duration for VM network tests
    tools:
      # Tool definitions
    directions:
      # Direction definitions
```

### Duration Priority

The duration is resolved in the following order:
1. **Category-level duration** (in `test_matrix.[category].duration`)
2. **Global default duration** (in `defaults.duration`)
3. **Fallback to 8 seconds** (if neither is specified)

Example:
```yaml
test_matrix:
  system-network:
    duration: 3        # System network tests will use 3 seconds
    # ... other config

  vm-network:
    # No duration specified, will use global default
    # ... other config

defaults:
  duration: 5          # Global default for categories without specific duration
```

In this example:
- `system-network` tests will use **3 seconds**
- `vm-network` tests will use **5 seconds** (global default)

### Tool Definition

```yaml
tools:
  - script: "tool_script.py"
    template: "sudo python3 {path} --arg1 {VAR1} --arg2 {VAR2} --direction {direction} --protocol {protocol}"
    protocols: ["tcp", "udp", "icmp"]
```

### Direction Definition

```yaml
directions:
  rx:
    SRC_IP: "{REMOTE_IP}"
    DST_IP: "{LOCAL_IP}"
  tx:
    SRC_IP: "{LOCAL_IP}"
    DST_IP: "{REMOTE_IP}"
```

## Variable Substitution

Variables are substituted in the following order:
1. Direction-specific variables (from `directions.[direction]`)
2. Built-in variables (`{path}`, `{direction}`, `{protocol}`)
3. Environment variables (from `variables.[category]`)

Variables support nested substitution, so `{SRC_IP}: "{REMOTE_IP}"` will be properly resolved.

## Complete Example

```yaml
metadata:
  name: "Performance Test Specification"
  version: "1.0"

variables:
  system-network:
    LOCAL_IP: "10.132.114.11"
    REMOTE_IP: "10.132.114.12"
    PHY_INTERFACE: "ens11"

test_matrix:
  system-network:
    duration: 3  # Fast tests for system network
    tools:
      - script: "system_tool.py"
        template: "sudo python3 {path} --phy-interface {PHY_INTERFACE} --src-ip {SRC_IP} --dst-ip {DST_IP} --direction {direction} --protocol {protocol}"
        protocols: ["tcp", "udp"]

    directions:
      rx:
        SRC_IP: "{REMOTE_IP}"
        DST_IP: "{LOCAL_IP}"
      tx:
        SRC_IP: "{LOCAL_IP}"
        DST_IP: "{REMOTE_IP}"

defaults:
  duration: 8  # Fallback duration
```

## Usage

Generate test cases using the specification:

```bash
python3 test/workflow/tools/test_case_generator.py \
  --test-config path/to/test-config.yaml \
  --spec-config path/to/spec-config.yaml \
  --output path/to/output.json
```