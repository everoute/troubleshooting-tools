# Kvm Virt Network - Analysis Overview

**Iteration:** iteration_001
**Date:** 2025-10-22 23:39:53
**Total Cases:** 24

## Summary Statistics

- Total test cases: 24
- Cases with latency data: 24
- Cases with throughput data: 24
- Cases with PPS data: 24
- Cases with resource data: 23

## Performance Summary

| Tool Case | Protocol | Dir | Latency Diff (%) | Throughput Diff (%) | PPS Diff (%) |
|-----------|----------|-----|------------------|---------------------|---------------|
| kvm_virt_network_case_10_tc... | tcp | rx | -1.81 | -8.7 | -0.3 |
| kvm_virt_network_case_11_tc... | tcp | rx | 1.91 | -33.23 | -2.82 |
| kvm_virt_network_case_12_tc... | tcp | rx | -11.01 | -11.16 | -1.19 |
| kvm_virt_network_case_13_tc... | tcp | rx | 2.95 | -26.15 | -12.14 |
| kvm_virt_network_case_14_tc... | tcp | rx | 1.52 | -17.85 | 4.11 |
| kvm_virt_network_case_15_tc... | tcp | rx | -3.99 | -4.02 | -10.95 |
| kvm_virt_network_case_16_tc... | tcp | rx | -3.29 | -5.58 | -12.84 |
| kvm_virt_network_case_17_tc... | tcp | rx | 11.64 | 14.02 | -4.56 |
| kvm_virt_network_case_18_tc... | tcp | rx | 18.34 | -11.68 | -6.24 |
| kvm_virt_network_case_19_tc... | tcp | rx | 1.48 | -19.4 | -14.6 |
| kvm_virt_network_case_1_tcp... | tcp | rx | -3.65 | -20.83 | -7.71 |
| kvm_virt_network_case_20_tc... | tcp | rx | 7.11 | -25.57 | 3.58 |
| kvm_virt_network_case_21_ud... | udp | rx | 8.39 | -11.55 | 6.97 |
| kvm_virt_network_case_22_tc... | tcp | rx | 2.37 | -20.12 | -3.98 |
| kvm_virt_network_case_23_tc... | tcp | rx | 12.41 | -25.05 | -0.01 |
| kvm_virt_network_case_24_tc... | tcp | rx | 11.71 | -24.21 | -5.09 |
| kvm_virt_network_case_2_tcp... | tcp | rx | -0.44 | -17.13 | -6.41 |
| kvm_virt_network_case_3_tcp... | tcp | rx | 7.15 | 5.32 | -9.22 |
| kvm_virt_network_case_4_tcp... | tcp | rx | -6.98 | -26.54 | -4.66 |
| kvm_virt_network_case_5_tcp... | tcp | rx | 3.68 | -3.57 | -0.94 |
| kvm_virt_network_case_6_tcp... | tcp | rx | -0.08 | -19.73 | -2.7 |
| kvm_virt_network_case_7_tcp... | tcp | rx | -3.74 | 14.08 | 2.45 |
| kvm_virt_network_case_8_tcp... | tcp | rx | -4.36 | -11.42 | -2.53 |
| kvm_virt_network_case_9_tcp... | tcp | rx | -0.11 | -12.72 | -3.85 |

## Notes

- Positive diff% for latency indicates performance degradation (higher latency)
- Negative diff% for throughput/PPS indicates performance degradation
- N/A indicates missing data

## Detailed Reports

1. **Latency Report**: `kvm_virt_network_latency_iteration_001.csv`
2. **Throughput Report**: `kvm_virt_network_throughput_iteration_001.csv`
3. **PPS Report**: `kvm_virt_network_pps_iteration_001.csv`
4. **Resources Report**: `kvm_virt_network_resources_iteration_001.csv`
