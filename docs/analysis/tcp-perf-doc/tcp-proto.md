From a TCP protocol perspective:

1. ACK Clocking Disruption: Variable RTT disrupts ACK clocking, causing burst sending
2. Congestion Window Inflation: Low RTT periods cause cwnd to grow aggressively
3. Queue Oscillation: Large buffers cause standing queues that TCP interprets as path capacity
4. Delivery Rate Estimation Issues: High RTT variance makes accurate bandwidth estimation difficult
