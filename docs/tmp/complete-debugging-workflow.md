# Complete Debugging Workflow for skb_segment Crash

## Problem Summary

**Crash**: `skb_segment+558` NULL pointer dereference (`list_skb` / `frag_list` is NULL)

**Mystery**: SKB has `SKB_GSO_UDP_TUNNEL` flag but:
- VM configured with Calico IPIP (no VXLAN)
- No VXLAN devices in VM
- No VXLAN on Host
- RX packets look like normal IPIP

**Hypothesis**: `gso_type` flag is incorrectly set, not real VXLAN traffic

## Two-Tool Debugging Approach

### Tool 1: skb_frag_list_watcher.py
**Purpose**: Find WHERE frag_list was cleared
**Answers**: "Who cleared frag_list but didn't reset gso_size?"

### Tool 2: skb_vxlan_source_detector.py
**Purpose**: Find WHERE UDP_TUNNEL flag was set
**Answers**: "Why does IPIP packet have VXLAN gso_type?"

## Complete Workflow

### Phase 1: Confirm Both Issues

#### Step 1.1: Run frag_list watcher
```bash
# Monitor frag_list modifications
sudo python ebpf-tools/performance/system-network/skb_frag_list_watcher.py \
    --gso-only \
    --verbose
```

**Look for**:
```
14:23:45   2   CREATE       skb_gro_receive_list   | NULL -> 0xdef456000
14:23:45   2   CLEAR        pskb_expand_head       | 0xdef456000 -> NULL [!!]
14:23:45   2   INCONSISTENT skb_segment            | 0x0 [CRITICAL]
```

**This shows**: frag_list creation → unexpected clearing → crash

#### Step 1.2: Run VXLAN source detector
```bash
# Check system and trace gso_type
sudo python ebpf-tools/performance/system-network/skb_vxlan_source_detector.py \
    --gso-changes-only
```

**Look for**:
```
STATIC: No VXLAN devices, IPIP configured ✓

TRACE:
14:23:45   2   VIRTIO_RX    receive_buf       | virtio_gso=UDP kernel_gso=UDP_TUNNEL [VXLAN FLAG!]
  flow=10.132.114.11->10.132.114.12 dev=eth0 gso_size=1348 encap=1
```

**This shows**: Where UDP_TUNNEL flag appears

### Phase 2: Identify Root Causes

Based on Tool 2 output, you'll see ONE of these patterns:

#### Pattern A: Virtio Sets UDP_TUNNEL
```
EVENT=VIRTIO_RX FUNCTION=receive_buf | virtio_gso=UDP kernel_gso=UDP_TUNNEL
```

**Root Cause**: Virtio GSO type conversion bug
- `virtio_net_hdr.gso_type = 3` (VIRTIO_NET_HDR_GSO_UDP)
- Incorrectly mapped to `SKB_GSO_UDP_TUNNEL` instead of `SKB_GSO_UDP_L4`

**Fix Location**: `drivers/net/virtio_net.c:receive_buf()`

#### Pattern B: GRO Adds UDP_TUNNEL
```
EVENT=GRO_COMPLETE FUNCTION=udp4_gro_complete | NONE -> UDP_TUNNEL [VXLAN ADDED!]
```

**Root Cause**: GRO misidentifies IPIP as UDP tunnel
- IPIP packet has `encapsulation=1`
- GRO completion mistakenly adds `SKB_GSO_UDP_TUNNEL`

**Fix Location**: `net/ipv4/udp_offload.c:udp4_gro_complete()`

#### Pattern C: Already Set on Entry
```
EVENT=GSO_SET FUNCTION=skb_segment | gso_type=UDP_TUNNEL
```

**Root Cause**: Inherited from earlier (trace back to Pattern A or B)

### Phase 3: Correlate Both Issues

Now run **BOTH tools simultaneously** to see the relationship:

```bash
# Terminal 1: Frag_list watcher
sudo python skb_frag_list_watcher.py --gso-only > /tmp/frag_list.log &

# Terminal 2: VXLAN detector
sudo python skb_vxlan_source_detector.py > /tmp/vxlan_source.log &

# Terminal 3: Trigger the crash
# (run your workload)

# Stop both
kill %1 %2
```

**Analyze correlation**:
```bash
# Compare timestamps
paste <(grep INCONSISTENT /tmp/frag_list.log) \
      <(grep UDP_TUNNEL /tmp/vxlan_source.log)
```

**Expected finding**:
```
Same SKB address appearing in both logs with matching timestamps
→ SKB has UDP_TUNNEL flag AND NULL frag_list
→ This causes crash in skb_udp_tunnel_segment
```

## Root Cause Decision Tree

```
Start: Crash in skb_segment with NULL frag_list + UDP_TUNNEL flag
  |
  ├─ Tool 2: Where is UDP_TUNNEL set?
  |  |
  |  ├─ In receive_buf (VIRTIO_RX event)
  |  |  → Virtio GSO type conversion bug
  |  |  → Fix: drivers/net/virtio_net.c
  |  |
  |  ├─ In udp4_gro_complete (GRO_COMPLETE event)
  |  |  → GRO misidentifies IPIP as UDP tunnel
  |  |  → Fix: net/ipv4/udp_offload.c
  |  |
  |  └─ Already set before any traced function
  |     → Check Host kernel (may happen on host before forwarding to VM)
  |
  └─ Tool 1: Why is frag_list cleared?
     |
     ├─ Cleared by pskb_expand_head
     |  → Header expansion during IP forwarding
     |  → Check: Does it properly handle GSO packets?
     |  → Fix: Ensure pskb_expand_head preserves frag_list for GSO
     |
     ├─ Cleared by __skb_linearize
     |  → Forced linearization
     |  → Check: Why is linearization triggered?
     |  → Fix: Call skb_gso_reset() after linearization
     |
     └─ Never created (NULL from start)
        → Check: Why did GRO not create frag_list?
        → May be related to wrong gso_type affecting GRO logic
```

## Specific Kernel Code to Examine

### Based on Tool 2 Output

#### If VIRTIO_RX event sets UDP_TUNNEL:

**File**: `drivers/net/virtio_net.c` (kernel 4.18.0-553.47.1)

Find the GSO type conversion code around line 800-1000:
```c
static void receive_buf(struct receive_queue *rq, void *buf,
                        unsigned int len, void **ctx)
{
    struct virtio_net_hdr_mrg_rxbuf *hdr = ...;

    // This is the suspicious code
    if (hdr->hdr.gso_type != VIRTIO_NET_HDR_GSO_NONE) {
        switch (hdr->hdr.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
        case VIRTIO_NET_HDR_GSO_TCPV4:
            skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
            break;
        case VIRTIO_NET_HDR_GSO_UDP:
            // BUG: Should this be SKB_GSO_UDP_L4 or SKB_GSO_UDP_TUNNEL?
            // For IPIP over virtio, what should this be?
            skb_shinfo(skb)->gso_type = ???;
            break;
        }
    }
}
```

**Question to answer**: What is `hdr->hdr.gso_type` for your IPIP packets?

#### If GRO_COMPLETE event adds UDP_TUNNEL:

**File**: `net/ipv4/udp_offload.c` (kernel 4.18.0-553.47.1)

Find `udp4_gro_complete()` around line 680-708:
```c
int udp4_gro_complete(struct sk_buff *skb, int nhoff)
{
    // Check this logic
    if (skb->encapsulation) {  // IPIP has encapsulation=1
        // BUG: Does this incorrectly set UDP_TUNNEL for IPIP?
        skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_TUNNEL_CSUM;
    }
}
```

**Question to answer**: Does IPIP packet incorrectly trigger the encapsulation branch?

### Based on Tool 1 Output

#### If pskb_expand_head clears frag_list:

**File**: `net/core/skbuff.c` (kernel 4.18.0-553.47.1)

Find `pskb_expand_head()` around line 1840-1920:
```c
int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail,
                     gfp_t gfp_mask)
{
    // Check if this properly handles frag_list for GSO packets
    // Does it preserve frag_list?
    // Does it call skb_gso_reset() if frag_list is lost?
}
```

## Expected Findings

### Most Likely Scenario

**Combination of bugs**:

1. **Primary Bug** (Tool 2): Virtio or GRO incorrectly sets `SKB_GSO_UDP_TUNNEL` for IPIP
   - IPIP packet arrives
   - Wrong gso_type flags set
   - Packet appears to be VXLAN but isn't

2. **Secondary Bug** (Tool 1): Some operation clears frag_list without updating gso_type
   - pskb_expand_head or __skb_linearize clears frag_list
   - But doesn't call skb_gso_reset()
   - GSO parameters (size, type) remain

3. **Crash**: GSO segmentation
   - skb_segment sees UDP_TUNNEL flag
   - Calls skb_udp_tunnel_segment
   - Expects VXLAN format with frag_list
   - Accesses NULL frag_list → CRASH

### Confidence Check

After running both tools, you should see:

```
[Tool 2] UDP_TUNNEL flag set at: <function_name>
         Time: 14:23:45.123
         SKB: 0xffff888abc123000

[Tool 1] frag_list cleared at: <function_name>
         Time: 14:23:45.124
         SKB: 0xffff888abc123000  (SAME SKB!)

[Crash] skb_segment
        Time: 14:23:45.125
        SKB: 0xffff888abc123000  (SAME SKB!)
```

**This proves**: Wrong gso_type + cleared frag_list = crash

## Developing the Fix

### Fix Strategy

Depending on root cause:

#### Fix A: Virtio GSO Conversion
```c
// In drivers/net/virtio_net.c:receive_buf()

case VIRTIO_NET_HDR_GSO_UDP:
    // OLD (buggy):
    // skb_shinfo(skb)->gso_type = SKB_GSO_UDP_TUNNEL;

    // NEW (correct):
    skb_shinfo(skb)->gso_type = SKB_GSO_UDP_L4;
    break;
```

#### Fix B: GRO Completion
```c
// In net/ipv4/udp_offload.c:udp4_gro_complete()

// OLD (buggy):
if (skb->encapsulation) {
    skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_TUNNEL_CSUM;
}

// NEW (correct):
if (skb->encapsulation && is_udp_tunnel(skb)) {  // Add check
    skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_TUNNEL_CSUM;
}
```

#### Fix C: Preserve frag_list or Reset GSO
```c
// In net/core/skbuff.c:pskb_expand_head()

// At end of function, if frag_list was lost:
if (old_frag_list && !new_frag_list && skb_is_gso(skb)) {
    // Lost frag_list during expansion, reset GSO
    skb_gso_reset(skb);
}
```

### Testing the Fix

1. **Apply patch** to kernel
2. **Rebuild kernel**
3. **Reboot VM**
4. **Run both tools** to verify:
   - No more UDP_TUNNEL flags on IPIP packets
   - OR frag_list is properly preserved
   - No more INCONSISTENT events
5. **Run workload** - should not crash

## Summary

### Two Problems, One Crash

**Problem 1** (Tool 2): Wrong gso_type flag
- IPIP packet incorrectly marked as UDP tunnel
- Virtio or GRO conversion bug

**Problem 2** (Tool 1): frag_list cleared without GSO reset
- pskb_expand_head or linearization clears frag_list
- GSO parameters not updated

**Result**: GSO tries to segment fake VXLAN packet without frag_list → NULL deref → crash

### Tools Answer Different Questions

| Question | Tool |
|----------|------|
| Why does IPIP have VXLAN flag? | skb_vxlan_source_detector.py |
| Where was frag_list cleared? | skb_frag_list_watcher.py |
| What's the exact sequence? | Run both simultaneously |

### Next Action

1. Run `skb_vxlan_source_detector.py` first
2. Identify WHERE UDP_TUNNEL is set (Virtio vs GRO vs other)
3. Run `skb_frag_list_watcher.py` to confirm frag_list issue
4. Examine kernel code at identified locations
5. Develop targeted patch
6. Test and verify

---

**Both tools are ready to use. Start with skb_vxlan_source_detector.py to identify the primary bug.**
