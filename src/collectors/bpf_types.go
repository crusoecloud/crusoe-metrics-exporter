package collectors

// LatencyStats matches the C struct latency_stats from tcp_latency.h
type LatencyStats struct {
	RequestCount   uint64
	TotalLatencyNs uint64
}

// ActiveRequest matches the C struct active_request from tcp_latency.h
type ActiveRequest struct {
	SendTimeNs uint64
	DestIP     uint32
	DestPort   uint16
	Padding    uint16
}
