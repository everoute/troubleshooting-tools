# BCC and Kernel Compatibility Issues

## Problem: BCC 0.15 with Kernel 5.10+

### Error Symptoms

When running BCC-based tools on kernel 5.10+ with BCC 0.15.0, you may encounter compilation errors:

```
error: use of undeclared identifier 'BPF_SK_LOOKUP'
error: use of undeclared identifier 'BPF_CGROUP_INET_SOCK_RELEASE'
```

### Root Cause

This is a **version mismatch** between BCC and kernel headers:

- **Kernel 5.10** (released Dec 2020) introduced new BPF program types and attach points
- **BCC 0.15.0** (released Jul 2020) was released before kernel 5.10 and doesn't define these new enums
- When BCC compiles BPF programs, it includes kernel headers that reference these new enums
- BCC's own headers don't define them, causing compilation failure

### Affected Environments

**Working combinations:**
- ✅ Kernel 4.19 + BCC 0.21 (newer BCC includes all definitions)
- ✅ Kernel 5.10 + BCC 0.18+ (BCC updated to support kernel 5.10)

**Problematic combination:**
- ❌ Kernel 5.10 + BCC 0.15 (BCC too old for kernel 5.10)

**Example from openEuler:**
```bash
$ rpm -qa | grep bcc
bcc-tools-0.15.0-2.oe1.x86_64
bcc-0.15.0-2.oe1.x86_64
python3-bpfcc-0.15.0-2.oe1.noarch

$ uname -r
5.10.0-247.0.0.oe1.v64.x86_64
```

### Timeline

| Date | Event |
|------|-------|
| Jul 2020 | BCC 0.15.0 released |
| Dec 2020 | Kernel 5.10 released with new BPF features |
| Mar 2021 | BCC 0.18.0 released with kernel 5.10 support |

---

## Solutions

### Solution 1: Upgrade BCC (Recommended)

Upgrade to BCC 0.18.0 or later:

```bash
# Check for updates in system repository
sudo yum update bcc bcc-tools python3-bpfcc

# Verify new version
rpm -qa | grep bcc
```

**Pros:**
- Clean solution, no code changes needed
- Gets latest BCC features and bug fixes
- Future-proof for newer kernels

**Cons:**
- Requires system package update
- May not be available in all repositories

### Solution 2: Add Compatibility Definitions (Workaround)

Our tools now include compatibility definitions in the BPF code:

```c
// Compatibility fixes for older BCC versions (0.15.0) with newer kernels (5.10+)
// BCC 0.15.0 doesn't define these enums that kernel 5.10+ expects
// Must be defined BEFORE including headers that use them
#ifndef BPF_SK_LOOKUP
#define BPF_SK_LOOKUP 36
#endif

#ifndef BPF_CGROUP_INET_SOCK_RELEASE
#define BPF_CGROUP_INET_SOCK_RELEASE 34  // NOT 9 (that's BPF_CGROUP_INET6_BIND)
#endif
```

This is added **before** including kernel headers (`#include <net/sock.h>` etc.).

**Pros:**
- Works without upgrading BCC
- No system changes required
- Backward compatible (doesn't break newer BCC)

**Cons:**
- Requires code modifications
- May need updates for future kernel versions
- Doesn't fix underlying version mismatch

### Solution 3: Downgrade Kernel (Not Recommended)

Downgrade to kernel 4.19 or earlier:

```bash
# Not recommended - loses kernel features
sudo yum downgrade kernel
```

**Cons:**
- Loses kernel 5.x features and security fixes
- Not sustainable long-term

---

## Technical Details

### Missing Enum Definitions

**BPF_SK_LOOKUP** (added in kernel 5.9):
- Location in kernel: `include/uapi/linux/bpf.h`
- Purpose: BPF program type for socket lookup
- Enum value: 36
- Usage: `enum bpf_attach_type` in `linux/bpf-netns.h`

**BPF_CGROUP_INET_SOCK_RELEASE** (added in kernel 5.9):
- Location in kernel: `include/uapi/linux/bpf.h`
- Purpose: cgroup attach point for socket release
- Enum value: 34 (NOT 9, which is BPF_CGROUP_INET6_BIND)
- Usage: `enum bpf_attach_type` in `linux/bpf-cgroup.h`

### Why This Happens

1. BCC tools compile BPF C code using kernel headers from `/lib/modules/$(uname -r)/build/include/`
2. Kernel 5.10 headers use these new enums in various header files
3. BCC 0.15's `bpf.h` doesn't define these enums
4. When BCC's clang frontend parses the kernel headers, it encounters undefined identifiers
5. Compilation fails

### Include Order Matters

The fix must be placed **before** including kernel headers:

```c
// ✅ CORRECT: Define before kernel includes
#ifndef BPF_SK_LOOKUP
#define BPF_SK_LOOKUP 36
#endif

#include <net/sock.h>  // This includes linux/bpf-netns.h which uses BPF_SK_LOOKUP
```

```c
// ❌ WRONG: Define after kernel includes
#include <net/sock.h>

#ifndef BPF_SK_LOOKUP
#define BPF_SK_LOOKUP 36
#endif
// Too late - error already occurred during #include <net/sock.h>
```

---

## Verification

### Check BCC Version

```bash
# Method 1: RPM (RHEL/CentOS/openEuler)
rpm -qa | grep bcc

# Method 2: Python module
python3 -c "import bcc; print(bcc.__version__)"

# Method 3: Check installed files
ls -l /usr/share/bcc/tools/
```

### Check Kernel Version

```bash
uname -r
```

### Test Compatibility

Create a minimal test script:

```python
#!/usr/bin/env python3
from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>

int test_probe(struct pt_regs *ctx) {
    return 0;
}
"""

try:
    b = BPF(text=bpf_text)
    print("✅ BCC and kernel are compatible")
except Exception as e:
    if "BPF_SK_LOOKUP" in str(e):
        print("❌ BCC version too old for kernel 5.10+")
        print("   Solution: Upgrade BCC or add compatibility definitions")
    else:
        print(f"❌ Other error: {e}")
```

---

## BCC and Kernel Version Matrix

| BCC Version | Kernel 4.14 | Kernel 4.19 | Kernel 5.4 | Kernel 5.10 | Kernel 5.15+ |
|-------------|-------------|-------------|------------|-------------|--------------|
| 0.15.0      | ✅          | ✅          | ⚠️         | ❌          | ❌           |
| 0.18.0      | ✅          | ✅          | ✅         | ✅          | ⚠️           |
| 0.21.0      | ✅          | ✅          | ✅         | ✅          | ✅           |
| 0.24.0+     | ✅          | ✅          | ✅         | ✅          | ✅           |

Legend:
- ✅ Fully compatible
- ⚠️ Mostly works, may have minor issues
- ❌ Known compatibility issues

---

## Best Practices

1. **Match versions**: Use BCC released after your kernel version
2. **Regular updates**: Keep BCC updated to support newer kernels
3. **Test compatibility**: Always test tools on target environment before deployment
4. **Use compatibility shims**: Add `#ifndef` guards for forward compatibility
5. **Document requirements**: Specify minimum BCC version in tool documentation

---

## References

- BCC Release Notes: https://github.com/iovisor/bcc/releases
- Kernel BPF documentation: https://www.kernel.org/doc/html/latest/bpf/
- BPF attach types: `include/uapi/linux/bpf.h` in kernel source
