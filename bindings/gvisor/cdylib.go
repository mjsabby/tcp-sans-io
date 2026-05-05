// Cgo bridge to the tcp-sans-io cdylib.
//
// Kept in a non-_test.go file because `go test` does not support `import "C"`
// directly inside `*_test.go` files. The test file
// (integration_test.go) consumes the Go-side wrappers exported here.

package gvisor

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

// State discriminants — must match src/state.rs.
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

// MaxPacket is the largest IP datagram the cdylib will stage.
const MaxPacket = 1500

// FFI error codes — must match src/error.rs.
const (
	errInvalidState     = -3
	errMalformedPacket  = -4
	errNotForUs         = -5
	errWouldBlock       = -6
	errConnectionReset  = -7
	errConnectionClosed = -8
)

// ErrConnectionClosed is returned by Recv when the peer has closed cleanly
// and the local receive ring is empty. Callers should treat it as EOF.
var ErrConnectionClosed = errors.New("tcp_recv: connection closed")

// ErrConnectionReset is returned by Recv when the connection was aborted by
// a peer RST (or local abort).
var ErrConnectionReset = errors.New("tcp_recv: connection reset")

// ErrWouldBlock is returned by Send when the send ring is full. Callers
// should pump more outbound packets and retry.
var ErrWouldBlock = errors.New("tcp_send: would block")

// ErrMalformedPacket is returned by InjectPacket on a packet whose IP or TCP
// header / checksum is invalid. Adversarial-channel tests expect this and
// rely on the protocol recovering via retransmission.
var ErrMalformedPacket = errors.New("tcp_inject_packet: malformed")

// ErrNotForUs is returned by InjectPacket on a packet that doesn't belong to
// this connection (different 4-tuple, non-TCP, etc.).
var ErrNotForUs = errors.New("tcp_inject_packet: not for us")

// ErrInvalidState is returned by InjectPacket once the handle has reached
// CLOSED (e.g. after a peer RST or post-TIME_WAIT). Adversarial-channel
// tests must tolerate it: in real networks late packets continue arriving
// after both endpoints have torn the connection down.
var ErrInvalidState = errors.New("tcp_inject_packet: invalid state")

// TcpHandle wraps a placement-init handle in caller-owned storage.
// The cdylib has no allocator linked; we provide the storage via C.malloc.
type TcpHandle struct {
	storage unsafe.Pointer
	h       *C.TcpStreamHandle
	start   time.Time
}

// AbiVersion returns the cdylib's stable ABI version.
func AbiVersion() uint32 {
	return uint32(C.tcp_abi_version())
}

// NewTcpHandle initialises a handle in fresh, zeroed storage.
func NewTcpHandle(localIP []byte, localPort uint16, remoteIP []byte, remotePort uint16, iss uint32, initialRtoMs uint32) (*TcpHandle, error) {
	if len(localIP) != 4 || len(remoteIP) != 4 {
		return nil, errors.New("IPs must be 4 bytes")
	}
	size := C.tcp_handle_size()
	if size == 0 {
		return nil, errors.New("tcp_handle_size returned 0")
	}
	storage := C.malloc(size)
	if storage == nil {
		return nil, errors.New("malloc failed")
	}
	C.memset(storage, 0, size)

	h := (*C.TcpStreamHandle)(storage)
	rc := C.tcp_init(
		h,
		(*C.uint8_t)(unsafe.Pointer(&localIP[0])), C.uint16_t(localPort),
		(*C.uint8_t)(unsafe.Pointer(&remoteIP[0])), C.uint16_t(remotePort),
		C.uint32_t(iss), C.uint32_t(initialRtoMs),
	)
	if rc != 0 {
		C.free(storage)
		return nil, fmt.Errorf("tcp_init: %d", int(rc))
	}
	return &TcpHandle{storage: storage, h: h, start: time.Now()}, nil
}

// Free destroys the handle and releases its backing storage.
func (t *TcpHandle) Free() {
	if t.storage == nil {
		return
	}
	C.tcp_destroy(t.h)
	C.free(t.storage)
	t.storage = nil
	t.h = nil
}

func (t *TcpHandle) now() C.uint64_t {
	return C.uint64_t(time.Since(t.start).Milliseconds())
}

func (t *TcpHandle) Connect() error {
	if rc := C.tcp_connect(t.h, t.now()); rc != 0 {
		return fmt.Errorf("tcp_connect: %d", int(rc))
	}
	return nil
}

// Listen transitions the handle from CLOSED to LISTEN. The remote
// endpoint configured at construction is wildcarded — the next inbound
// SYN will pin a remote and start the handshake.
func (t *TcpHandle) Listen() error {
	if rc := C.tcp_listen(t.h, t.now()); rc != 0 {
		return fmt.Errorf("tcp_listen: %d", int(rc))
	}
	return nil
}

// SetCookieSecret installs a 16-byte secret that switches the listener
// into stateless RFC 4987 SYN-cookie mode. `secret` must be exactly 16
// bytes from a CSPRNG.
func (t *TcpHandle) SetCookieSecret(secret []byte) error {
	if len(secret) != 16 {
		return errors.New("cookie secret must be exactly 16 bytes")
	}
	rc := C.tcp_set_cookie_secret(t.h, (*C.uint8_t)(unsafe.Pointer(&secret[0])))
	if rc != 0 {
		return fmt.Errorf("tcp_set_cookie_secret: %d", int(rc))
	}
	return nil
}

func (t *TcpHandle) Close() error {
	if rc := C.tcp_close(t.h, t.now()); rc != 0 {
		return fmt.Errorf("tcp_close: %d", int(rc))
	}
	return nil
}

func (t *TcpHandle) Tick() error {
	if rc := C.tcp_tick(t.h, t.now()); rc != 0 {
		return fmt.Errorf("tcp_tick: %d", int(rc))
	}
	return nil
}

func (t *TcpHandle) State() uint8 {
	return uint8(C.tcp_state(t.h))
}

func (t *TcpHandle) Poll() uint32 {
	return uint32(C.tcp_poll(t.h))
}

func (t *TcpHandle) Send(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	var written C.size_t
	rc := C.tcp_send(t.h,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		&written)
	if rc != 0 {
		if int(rc) == errWouldBlock {
			return 0, ErrWouldBlock
		}
		return 0, fmt.Errorf("tcp_send: %d", int(rc))
	}
	return int(written), nil
}

func (t *TcpHandle) Recv(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var read C.size_t
	rc := C.tcp_recv(t.h,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.size_t(len(buf)),
		&read)
	if rc != 0 {
		switch int(rc) {
		case errConnectionClosed:
			return 0, ErrConnectionClosed
		case errConnectionReset:
			return 0, ErrConnectionReset
		}
		return 0, fmt.Errorf("tcp_recv: %d", int(rc))
	}
	return int(read), nil
}

func (t *TcpHandle) ExtractPacket(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, errors.New("zero-length extract buffer")
	}
	var written C.size_t
	rc := C.tcp_extract_packet(t.h,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.size_t(len(buf)),
		&written)
	if rc != 0 {
		return 0, fmt.Errorf("tcp_extract_packet: %d", int(rc))
	}
	return int(written), nil
}

func (t *TcpHandle) InjectPacket(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	rc := C.tcp_inject_packet(t.h,
		(*C.uint8_t)(unsafe.Pointer(&packet[0])),
		C.size_t(len(packet)),
		t.now())
	if rc != 0 {
		switch int(rc) {
		case errMalformedPacket:
			return ErrMalformedPacket
		case errNotForUs:
			return ErrNotForUs
		case errInvalidState:
			return ErrInvalidState
		}
		return fmt.Errorf("tcp_inject_packet: %d", int(rc))
	}
	return nil
}

// DebugSnapshot is a compact, diagnostic-only view of cdylib internal state.
// Used by integration tests to surface what the cdylib is doing when the
// protocol wedges. The shape mirrors crate::tcb::DebugSnapshot.
type DebugSnapshot struct {
	SndUna      uint32
	SndNxt      uint32
	SndWnd      uint32
	RcvNxt      uint32
	Cwnd        uint32
	Ssthresh    uint32
	RtoMs       uint32
	RtoDeadline uint64
	NowMs       uint64
	SendRingLen uint32
	RecvRingLen uint32
	OoStart     uint32
	OoLen       uint32
	TxLen       uint32
	PendingAck  bool
	DupAckCount uint8
	State       uint8
}

func (t *TcpHandle) DebugSnapshot() DebugSnapshot {
	var raw C.TcpDebugSnapshot
	C.tcp_debug_snapshot(t.h, &raw)
	return DebugSnapshot{
		SndUna:      uint32(raw.snd_una),
		SndNxt:      uint32(raw.snd_nxt),
		SndWnd:      uint32(raw.snd_wnd),
		RcvNxt:      uint32(raw.rcv_nxt),
		Cwnd:        uint32(raw.cwnd),
		Ssthresh:    uint32(raw.ssthresh),
		RtoMs:       uint32(raw.rto_ms),
		RtoDeadline: uint64(raw.rto_deadline),
		NowMs:       uint64(raw.now_ms),
		SendRingLen: uint32(raw.send_ring_len),
		RecvRingLen: uint32(raw.recv_ring_len),
		OoStart:     uint32(raw.oo_start),
		OoLen:       uint32(raw.oo_len),
		TxLen:       uint32(raw.tx_len),
		PendingAck:  raw.pending_ack != 0,
		DupAckCount: uint8(raw.dup_ack_count),
		State:       uint8(raw.state),
	}
}
