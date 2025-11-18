<!-- Copilot / AI agent guidance for the troubleshooting-tools repository -->

# Copilot instructions (concise)

Purpose
- Help the AI agent be immediately productive in this eBPF-based network troubleshooting repo.

Essential context (big picture)
- This repo is an eBPF-based network troubleshooting and performance analysis toolset for virtualized environments. Two main functional areas:
  - measurement-tools / ebpf-tools: BCC Python + bpftrace probes that attach kprobes/tracepoints and expose data via BPF maps to userspace.
  - traffic-analyzer: higher-level PCAP/TCP analysis (designs live under `docs/design/traffic-analyzer/claude/`).
- Data flow: kernel eBPF program → BPF maps → Python userspace processing → stdout (tools emit to stdout by default).

Key files & directories to consult (examples)
- `ebpf-tools/` (or `measurement-tools/`): place new probes next to peers and include CLI usage in module docstring.
- `test/workflow/`: spec-driven test framework (YAML specs → generated cases). See `test/workflow/test_case_generator.py`.
- `AGENTS.md`, `CLAUDE.md`, `README.md`: primary repo-level conventions and runnable commands (examples below).
- `kprobe_functions.txt`: available kprobe points reference.

Concrete run examples (use when suggesting commands)
- Run a host collector (root required):
  `sudo python3 ebpf-tools/performance/system-network/system_network_latency_summary.py --iface enp5s0 --duration 30`
- Dry-run bpftrace program:
  `sudo bpftrace -d measurement-tools/other/trace-abnormal-arp.bt`
- Remote validation helper:
  `python3 test/tools/bpf_remote_executor.py smartx@lab-host /home/smartx/tools "sudo python3 ... --duration 20" --local-script ./script.py`

Repository-specific conventions (do not invent)
- Python: PEP8, four-space indentation, snake_case filenames, preserve `#!/usr/bin/env python3` and `if __name__ == "__main__":`.
- Argparse pattern: tools accept consistent flags (e.g. `--src-ip`, `--dst-ip`, `--vm-interface`, `--phy-interface`, `--debug`). Keep argparse helpers consistent.
- bpftrace files: lowercase-kebab `.bt` with header comment listing attach points and expected metrics.
- BPF compatibility: tools include fallback import pattern for `bcc`/`bpfcc`:
  ```py
  try:
      from bcc import BPF
  except ImportError:
      from bpfcc import BPF
  ```

Safety, scope and non-goals (must follow)
- All BPF tools require root; DO NOT run untested programs on production systems. Prefer lab hosts.
- BPF stack limit ~512 bytes — avoid large on-stack structures.
- NEVER proactively create new top-level docs or README files unless explicitly asked (this repo forbids unsolicited doc creation).
- ALWAYS prefer editing existing files rather than adding new files where possible.
- Avoid emojis and non-English (Chinese) characters in logs/prints per local conventions.

PR and commit guidance for AI edits
- Use Conventional Commits: `feat:`, `fix:`, `chore:` and keep subject <=72 chars. When applicable add scope, e.g. `feat(perf): add vm latency summary`.
- PR description must include affected modules, kernel prerequisites, validation commands used, and doc updates (sanitized of hostnames/IPs).

Where to look next while coding
- `docs/` for design decisions and kernel compatibility notes (`docs/analysis/` and `docs/design/`).
- `test/debug/` for reproducer scripts used in triage.

If unsure or missing context
- Ask for the target kernel version and whether this runs on a host or a VM. Ask which interfaces the user expects (e.g. `enp5s0`, `vnet0`).
- When proposing commands, always include a one-line safety reminder: "requires root, run in lab environment first".

Quick checklist for AI-generated changes
- Keep the same shebang and argparse pattern.
- Add or update CLI help text and an example invocation in the module docstring.
- If touching an eBPF program, ensure stack usage is within limits and use maps for larger state.

If this file needs expansion or merging
- If you want extra project-specific snippets (common helper functions, example unit tests), ask and I will add them after reviewing the specific target files to avoid inventing structure.

-- end --
