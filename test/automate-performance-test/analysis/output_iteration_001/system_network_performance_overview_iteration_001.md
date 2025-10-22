# System Network Performance - Analysis Overview

**Iteration:** iteration_001
**Date:** 2025-10-22 23:39:53
**Total Cases:** 10

## Summary Statistics

- Total test cases: 10
- Cases with latency data: 10
- Cases with throughput data: 10
- Cases with PPS data: 10
- Cases with resource data: 8

## Performance Summary

| Tool Case | Protocol | Dir | Latency Diff (%) | Throughput Diff (%) | PPS Diff (%) |
|-----------|----------|-----|------------------|---------------------|---------------|
| system_network_performance_... | tcp | tx | 21.76 | 30.13 | -4.03 |
| system_network_performance_... | tcp | rx | 93.5 | -32.83 | -5.3 |
| system_network_performance_... | tcp | tx | 35.76 | -33.59 | -20.81 |
| system_network_performance_... | udp | rx | -2.44 | 3.18 | -9.76 |
| system_network_performance_... | udp | tx | 4.62 | -5.53 | -9.53 |
| system_network_performance_... | tcp | rx | 139.11 | -12.51 | -1.46 |
| system_network_performance_... | tcp | tx | 53.19 | -25.92 | -29.44 |
| system_network_performance_... | udp | rx | 37.32 | -4.91 | -5.05 |
| system_network_performance_... | udp | tx | 34.29 | 2.35 | -4.54 |
| system_network_performance_... | tcp | rx | 50.44 | 11.68 | -0.18 |

## Notes

- Positive diff% for latency indicates performance degradation (higher latency)
- Negative diff% for throughput/PPS indicates performance degradation
- N/A indicates missing data

## Detailed Reports

1. **Latency Report**: `system_network_performance_latency_iteration_001.csv`
2. **Throughput Report**: `system_network_performance_throughput_iteration_001.csv`
3. **PPS Report**: `system_network_performance_pps_iteration_001.csv`
4. **Resources Report**: `system_network_performance_resources_iteration_001.csv`
