# Disable debug package and file classification errors
%define debug_package %{nil}
%define _binary_payload w9.gzdio

# Disable Python bytecode compilation (tools may use Python 2 or 3 depending on target system)
%define __python %{nil}

# Disable shebang mangling (tools use #!/usr/bin/env python for Python 2/3 compatibility)
%undefine __brp_mangle_shebangs
%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g' | sed -e 's!/usr/lib[^[:space:]]*/brp-mangle-shebangs[[:space:]].*$!!g')

Name:           measurement-tools
Version:        %{?version}%{!?version:1.0.0}
Release:        %{?release_ver}%{!?release_ver:1}%{?dist}
Summary:        eBPF-based network troubleshooting and performance analysis tools

License:        Proprietary 
Group:          Applications/System
BuildArch:      noarch

Source0:        %{name}-%{version}.tar.gz

# Disable automatic dependency generation (pure scripts)
AutoReqProv:    no

%description
eBPF-based network troubleshooting and performance analysis toolset
for virtualized environments. Includes BCC Python tools and bpftrace
scripts for packet drop monitoring, latency analysis, OVS debugging,
and virtualization network tracing.

Tools categories:
- linux-network-stack: Packet drop monitoring, connection tracking
- performance: Host and VM network latency analysis
- ovs: Open vSwitch megaflow, upcall, kernel module monitoring
- kvm-virt-network: Virtio/TUN/TAP/vhost monitoring
- cpu: CPU and scheduler analysis
- other: Additional tracers (ARP, qdisc, VPC datapath)
- boundary-detection: Network boundary drop detection (system and VM level path tracers)

%prep
%setup -q -n %{name}-%{version}

%build
# Nothing to build - pure scripts

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/measurement-tools

# Copy all tool directories
for dir in cpu kvm-virt-network linux-network-stack other ovs performance boundary-detection; do
    if [ -d "$dir" ]; then
        cp -rp "$dir" %{buildroot}/usr/share/measurement-tools/
    fi
done

# Remove Python cache directories
find %{buildroot}/usr/share/measurement-tools -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find %{buildroot}/usr/share/measurement-tools -type f -name "*.pyc" -delete 2>/dev/null || true

# Remove bpftrace scripts (not included in this package)
find %{buildroot}/usr/share/measurement-tools -type f -name "*.bt" -delete 2>/dev/null || true

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/usr/share/measurement-tools

%changelog
* Mon Mar 09 2026 - 1.1.0-1
- Add boundary-detection module with 6 path tracer tools (system and VM level)
- Add kvm_vhost_tun_latency_no_discovery_details and tun_tx_to_kvm_irq tools
- Add performance tools: deploy_full_mesh_icmp_tracer, OVS internal port latency, TCP perf analyzers
- Fix IP byte order in trace_conntrack and trace_ip_defrag
- Fix BPF context type in system_network_icmp_rtt
- Improve GCC optimized function handling across multiple tools
- Enhance kernel_icmp_rtt with TX/RX direction and bond interface support
- Add --stage-latency mode to system/vm network latency summary tools
- Add --l4-protocol filter to eth_drop, --drops-only/--summary to qdisc_drop_trace
- Remove deprecated vm_pair_latency tool

* Mon Nov 25 2024 - 1.0.0-1
- Initial release
- Include BCC Python tools and bpftrace scripts
- Support for packet drop monitoring, latency analysis
- OVS and virtualization network tracing tools
