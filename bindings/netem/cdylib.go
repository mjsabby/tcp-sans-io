// Cgo bridge to the tcp-sans-io cdylib for the benchmark endpoint.
//
// Only the entry points present in every ABI-v2 build are used here, so the
// same endpoint can also drive an older build of the library (see
// cdylib_stats.go / cdylib_oldabi.go and `bench.sh --baseline-lib`).

package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -ltcp_sans_io -Wl,-rpath,${SRCDIR}/../../target/release
#include <stdint.h>
#include <stdlib.h>
#include "tcp_sans_io.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"time"
	"unsafe"
)

const (
	stateClosed      = 0
	stateEstablished = 2
	stateFinWait2    = 4
	stateTimeWait    = 6
	stateCloseWait   = 7
	stateLastAck     = 8
)

const (
	errInvalidState     = -3
	errMalformedPacket  = -4
	errNotForUs         = -5
	errWouldBlock       = -6
	errConnectionReset  = -7
	errConnectionClosed = -8
)

var (
	errClosed = errors.New("connection closed by peer")
	errReset  = errors.New("connection reset")
)

// handle owns one TCB in C-heap storage (never moved by the Go GC).
type handle struct {
	storage unsafe.Pointer
	h       *C.struct_TcpStreamHandle
	epoch   time.Time
}

// nowMs is the monotonic host clock handed to the stack.
func (t *handle) nowMs() uint64 { return uint64(time.Since(t.epoch).Milliseconds()) }

func newHandle(local, remote [4]byte, lport, rport uint16, iss uint32) (*handle, error) {
	storage := C.aligned_alloc(C.tcp_handle_align(), C.tcp_handle_size())
	if storage == nil {
		return nil, errors.New("out of memory")
	}
	rc := C.tcp_init((*C.struct_TcpStreamHandle)(storage),
		(*C.uint8_t)(unsafe.Pointer(&local[0])), C.uint16_t(lport),
		(*C.uint8_t)(unsafe.Pointer(&remote[0])), C.uint16_t(rport),
		C.uint32_t(iss), 1000)
	if rc != 0 {
		C.free(storage)
		return nil, fmt.Errorf("tcp_init: %d", rc)
	}
	return &handle{storage: storage, h: (*C.struct_TcpStreamHandle)(storage), epoch: time.Now()}, nil
}

func (t *handle) free() {
	C.tcp_destroy(t.h)
	C.free(t.storage)
}

func check(name string, rc C.int32_t) error {
	if rc != 0 {
		return fmt.Errorf("%s: %d", name, rc)
	}
	return nil
}

func (t *handle) connect() error { return check("tcp_connect", C.tcp_connect(t.h, C.uint64_t(t.nowMs()))) }
func (t *handle) close() error   { return check("tcp_close", C.tcp_close(t.h, C.uint64_t(t.nowMs()))) }
func (t *handle) tick() error    { return check("tcp_tick", C.tcp_tick(t.h, C.uint64_t(t.nowMs()))) }
func (t *handle) state() uint8   { return uint8(C.tcp_state(t.h)) }

func (t *handle) send(b []byte) (int, error) {
	var n C.size_t
	rc := C.tcp_send(t.h, (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b)), &n)
	if rc == errWouldBlock {
		return 0, nil
	}
	return int(n), check("tcp_send", rc)
}

func (t *handle) recv(b []byte) (int, error) {
	var n C.size_t
	switch rc := C.tcp_recv(t.h, (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b)), &n); rc {
	case 0:
		return int(n), nil
	case errConnectionClosed:
		return 0, errClosed
	case errConnectionReset:
		return 0, errReset
	default:
		return 0, fmt.Errorf("tcp_recv: %d", rc)
	}
}

func (t *handle) extract(buf []byte) (int, error) {
	var n C.size_t
	rc := C.tcp_extract_packet(t.h, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &n)
	return int(n), check("tcp_extract_packet", rc)
}

// inject feeds one datagram; segments that are not ours or malformed are
// counted by the caller and otherwise ignored, as a real host would.
func (t *handle) inject(pkt []byte) (accepted bool, err error) {
	switch rc := C.tcp_inject_packet(t.h, (*C.uint8_t)(unsafe.Pointer(&pkt[0])), C.size_t(len(pkt)),
		C.uint64_t(t.nowMs())); rc {
	case 0:
		return true, nil
	case errMalformedPacket, errNotForUs, errInvalidState:
		return false, nil
	default:
		return false, fmt.Errorf("tcp_inject_packet: %d", rc)
	}
}
