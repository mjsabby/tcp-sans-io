//go:build !oldabi

package main

/*
#include "tcp_sans_io.h"
*/
import "C"

import "unsafe"

// nextDeadline is the absolute stack-clock time of the next timer event.
func (t *handle) nextDeadline() (uint64, bool) {
	d := uint64(C.tcp_next_deadline(t.h))
	return d, d != ^uint64(0)
}

// setSecret keys timestamp offsets / ISNs, as an internet-facing host must.
func (t *handle) setSecret(secret [16]byte) error {
	return check("tcp_set_secret", C.tcp_set_secret(t.h, (*C.uint8_t)(unsafe.Pointer(&secret[0]))))
}

func (t *handle) stats() map[string]any {
	var s C.TcpStats
	if C.tcp_get_stats(t.h, &s) != 0 {
		return nil
	}
	return map[string]any{
		"segs_out":           uint64(s.segs_out),
		"segs_in":            uint64(s.segs_in),
		"bytes_sent":         uint64(s.bytes_sent),
		"bytes_retrans":      uint64(s.bytes_retrans),
		"bytes_received":     uint64(s.bytes_received),
		"dup_bytes_received": uint64(s.dup_bytes_received),
		"segs_retrans":       uint64(s.segs_retrans),
		"dsacks_received":    uint64(s.dsacks_received),
		"fast_recoveries":    uint32(s.fast_recoveries),
		"rto_count":          uint32(s.rto_count),
		"tlp_count":          uint32(s.tlp_count),
		"ooo_drops":          uint32(s.ooo_drops),
		"oow_suppressed":     uint32(s.oow_suppressed),
		"srtt_ms":            uint32(s.srtt_ms),
		"min_rtt_ms":         uint32(s.min_rtt_ms),
		"cwnd":               uint32(s.cwnd),
		"ssthresh":           uint32(s.ssthresh),
		"mss":                uint32(s.mss),
	}
}
