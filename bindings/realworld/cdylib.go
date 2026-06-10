// Cgo bridge to the tcp-sans-io cdylib for the real-world interop tests.
// Mirrors bindings/netem/cdylib.go with the addition of Listen() for
// passive-open scenarios (so the cdylib can host an HTTP echo server
// that a real curl client dials into).

package realworld

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -ltcp_sans_io -Wl,-rpath,${SRCDIR}/../../target/release
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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
	StateClosed      uint8 = 0
	StateSynSent     uint8 = 1
	StateEstablished uint8 = 2
	StateFinWait1    uint8 = 3
	StateFinWait2    uint8 = 4
	StateClosing     uint8 = 5
	StateTimeWait    uint8 = 6
	StateCloseWait   uint8 = 7
	StateLastAck     uint8 = 8
	StateListen      uint8 = 9
	StateSynRcvd     uint8 = 10
)

const MaxPacket = 1500

const (
	errInvalidState     = -3
	errMalformedPacket  = -4
	errNotForUs         = -5
	errWouldBlock       = -6
	errConnectionReset  = -7
	errConnectionClosed = -8
)

var (
	ErrConnectionClosed = errors.New("tcp_recv: connection closed")
	ErrConnectionReset  = errors.New("tcp_recv: connection reset")
	ErrWouldBlock       = errors.New("tcp_send: would block")
	ErrMalformedPacket  = errors.New("tcp_inject_packet: malformed")
	ErrNotForUs         = errors.New("tcp_inject_packet: not for us")
	ErrInvalidState     = errors.New("tcp_inject_packet: invalid state")
)

func StateName(s uint8) string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateSynSent:
		return "SYN_SENT"
	case StateEstablished:
		return "ESTABLISHED"
	case StateFinWait1:
		return "FIN_WAIT_1"
	case StateFinWait2:
		return "FIN_WAIT_2"
	case StateClosing:
		return "CLOSING"
	case StateTimeWait:
		return "TIME_WAIT"
	case StateCloseWait:
		return "CLOSE_WAIT"
	case StateLastAck:
		return "LAST_ACK"
	case StateListen:
		return "LISTEN"
	case StateSynRcvd:
		return "SYN_RCVD"
	}
	return fmt.Sprintf("?%d", s)
}

type TcpHandle struct {
	storage unsafe.Pointer
	handle  *C.struct_TcpStreamHandle
	start   time.Time
}

// now returns milliseconds from a monotonic origin. The FFI contract
// requires a monotonic, non-decreasing now_ms; time.Now().UnixMilli()
// is wall clock (Go strips the monotonic reading in UnixMilli) and can
// step backwards under NTP, stalling every stack timer for the size of
// the step. time.Since uses the monotonic reading.
func (h *TcpHandle) now() C.uint64_t {
	return C.uint64_t(time.Since(h.start).Milliseconds())
}

func NewTcpHandle(localIP []byte, localPort uint16, remoteIP []byte, remotePort uint16,
	iss uint32, initialRtoMs uint32) (*TcpHandle, error) {
	if len(localIP) != 4 || len(remoteIP) != 4 {
		return nil, fmt.Errorf("IP must be 4 bytes")
	}
	size := C.tcp_handle_size()
	storage := C.calloc(1, C.size_t(size))
	if storage == nil {
		return nil, fmt.Errorf("oom for handle storage")
	}
	rc := C.tcp_init(
		(*C.struct_TcpStreamHandle)(storage),
		(*C.uchar)(unsafe.Pointer(&localIP[0])),
		C.uint16_t(localPort),
		(*C.uchar)(unsafe.Pointer(&remoteIP[0])),
		C.uint16_t(remotePort),
		C.uint32_t(iss),
		C.uint32_t(initialRtoMs),
	)
	if rc != 0 {
		C.free(storage)
		return nil, fmt.Errorf("tcp_init: %d", rc)
	}
	return &TcpHandle{
		storage: storage,
		handle:  (*C.struct_TcpStreamHandle)(storage),
		start:   time.Now(),
	}, nil
}

func (h *TcpHandle) Free() {
	if h.storage != nil {
		C.tcp_destroy(h.handle)
		C.free(h.storage)
		h.storage = nil
		h.handle = nil
	}
}

func (h *TcpHandle) Connect() error {
	rc := C.tcp_connect(h.handle, h.now())
	if rc != 0 {
		return fmt.Errorf("tcp_connect: %d", rc)
	}
	return nil
}

func (h *TcpHandle) Listen() error {
	rc := C.tcp_listen(h.handle, h.now())
	if rc != 0 {
		return fmt.Errorf("tcp_listen: %d", rc)
	}
	return nil
}

func (h *TcpHandle) Close() error {
	rc := C.tcp_close(h.handle, h.now())
	if rc != 0 {
		return fmt.Errorf("tcp_close: %d", rc)
	}
	return nil
}

func (h *TcpHandle) State() uint8 {
	return uint8(C.tcp_state(h.handle))
}

func (h *TcpHandle) Tick() error {
	rc := C.tcp_tick(h.handle, h.now())
	if rc != 0 {
		return fmt.Errorf("tcp_tick: %d", rc)
	}
	return nil
}

func (h *TcpHandle) Send(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	var written C.size_t
	rc := C.tcp_send(h.handle, (*C.uchar)(unsafe.Pointer(&b[0])), C.size_t(len(b)), &written)
	switch rc {
	case 0:
		return int(written), nil
	case errWouldBlock:
		return 0, ErrWouldBlock
	default:
		return 0, fmt.Errorf("tcp_send: %d", rc)
	}
}

func (h *TcpHandle) Recv(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	var read C.size_t
	rc := C.tcp_recv(h.handle, (*C.uchar)(unsafe.Pointer(&b[0])), C.size_t(len(b)), &read)
	switch rc {
	case 0:
		return int(read), nil
	case errConnectionClosed:
		return 0, ErrConnectionClosed
	case errConnectionReset:
		return 0, ErrConnectionReset
	default:
		return 0, fmt.Errorf("tcp_recv: %d", rc)
	}
}

func (h *TcpHandle) ExtractPacket(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var written C.size_t
	rc := C.tcp_extract_packet(h.handle, (*C.uchar)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &written)
	if rc != 0 {
		return 0, fmt.Errorf("tcp_extract_packet: %d", rc)
	}
	return int(written), nil
}

func (h *TcpHandle) InjectPacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	rc := C.tcp_inject_packet(h.handle, (*C.uchar)(unsafe.Pointer(&pkt[0])), C.size_t(len(pkt)),
		h.now())
	switch rc {
	case 0:
		return nil
	case errMalformedPacket:
		return ErrMalformedPacket
	case errNotForUs:
		return ErrNotForUs
	case errInvalidState:
		return ErrInvalidState
	default:
		return fmt.Errorf("tcp_inject_packet: %d", rc)
	}
}
