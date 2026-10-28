//go:build oldabi

package main

// Older builds lack tcp_next_deadline / tcp_get_stats / tcp_set_secret:
// poll timers every millisecond and report no counters.

func (t *handle) nextDeadline() (uint64, bool) { return t.nowMs() + 1, true }
func (t *handle) setSecret([16]byte) error    { return nil }
func (t *handle) stats() map[string]any       { return nil }
