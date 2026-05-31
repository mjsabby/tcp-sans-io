// UDP transport with central reader goroutine + 5-tuple demux.
//
// The Rust server holds many TCBs on a single UDP socket. On the
// driver side, *every* client (mini-client or adversary) shares a
// single outbound UDP socket too — and the server's replies all come
// back to that single socket. To avoid 10K goroutines racing on
// `ReadFromUDP`, we run one central reader goroutine that parses each
// inbound encapsulated IPv4+TCP packet and dispatches to a per-client
// bounded inbox keyed on (client_src_ip, client_src_port).

package wgserver

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Transport owns the shared UDP socket and the (src_ip, src_port) →
// inbox routing table. Mini-clients and adversary tests register an
// inbox with `RegisterInbox` before sending their first packet.
type Transport struct {
	conn  *net.UDPConn
	peer  *net.UDPAddr
	mu    sync.RWMutex
	boxes map[demuxKey]*Inbox
	stop  chan struct{}
	wg    sync.WaitGroup
	// Counters for tests to inspect.
	mux struct {
		sync.Mutex
		rx       uint64
		tx       uint64
		dropped  uint64 // no matching inbox
		mismatch uint64 // parse failure
	}
}

type demuxKey struct {
	srcIP   [4]byte
	srcPort uint16
}

// Inbox holds packets routed to a specific (client_src_ip, client_src_port).
type Inbox struct {
	ch       chan []byte
	key      demuxKey
	owner    *Transport
	closed   bool
	closeMu  sync.Mutex
}

// NewTransport opens a UDP socket bound to `bind` (use ":0" for
// ephemeral) and points outbound traffic at `peer`.
func NewTransport(bind, peer string) (*Transport, error) {
	laddr, err := net.ResolveUDPAddr("udp4", bind)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", bind, err)
	}
	raddr, err := net.ResolveUDPAddr("udp4", peer)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", peer, err)
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, fmt.Errorf("listen %q: %w", laddr, err)
	}
	// Bump kernel buffers; matters for the 10K test.
	_ = conn.SetReadBuffer(16 * 1024 * 1024)
	_ = conn.SetWriteBuffer(16 * 1024 * 1024)

	t := &Transport{
		conn:  conn,
		peer:  raddr,
		boxes: make(map[demuxKey]*Inbox),
		stop:  make(chan struct{}),
	}
	t.wg.Add(1)
	go t.reader()
	return t, nil
}

// LocalAddr returns the bound UDP address (useful when bind was ":0").
func (t *Transport) LocalAddr() *net.UDPAddr {
	return t.conn.LocalAddr().(*net.UDPAddr)
}

// Close stops the reader and closes the socket. Any pending Inbox
// channels are closed.
func (t *Transport) Close() error {
	close(t.stop)
	_ = t.conn.SetReadDeadline(time.Now().Add(-1 * time.Second))
	err := t.conn.Close()
	t.wg.Wait()
	t.mu.Lock()
	for _, box := range t.boxes {
		box.closeNoUnregister()
	}
	t.boxes = map[demuxKey]*Inbox{}
	t.mu.Unlock()
	return err
}

// RegisterInbox installs a bounded inbox for the given (srcIP, srcPort)
// pair. Inbox.Close() must be called to free the slot when the client
// goroutine terminates.
func (t *Transport) RegisterInbox(srcIP [4]byte, srcPort uint16, capacity int) *Inbox {
	if capacity <= 0 {
		capacity = 32
	}
	k := demuxKey{srcIP: srcIP, srcPort: srcPort}
	box := &Inbox{
		ch:    make(chan []byte, capacity),
		key:   k,
		owner: t,
	}
	t.mu.Lock()
	t.boxes[k] = box
	t.mu.Unlock()
	return box
}

// SendTo writes a raw IPv4+TCP packet to the configured peer via the
// shared UDP socket.
func (t *Transport) SendTo(pkt []byte) error {
	_, err := t.conn.WriteToUDP(pkt, t.peer)
	if err == nil {
		t.mux.Lock()
		t.mux.tx++
		t.mux.Unlock()
	}
	return err
}

// Stats snapshot.
func (t *Transport) Stats() (rx, tx, dropped, mismatch uint64) {
	t.mux.Lock()
	defer t.mux.Unlock()
	return t.mux.rx, t.mux.tx, t.mux.dropped, t.mux.mismatch
}

// reader is the central goroutine.
func (t *Transport) reader() {
	defer t.wg.Done()
	buf := make([]byte, 2048)
	for {
		select {
		case <-t.stop:
			return
		default:
		}
		_ = t.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := t.conn.ReadFromUDP(buf)
		if err != nil {
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				continue
			}
			// Closed socket → exit.
			return
		}
		if n == 0 {
			continue
		}
		t.mux.Lock()
		t.mux.rx++
		t.mux.Unlock()

		// Parse just enough to identify the (dst_ip, dst_port) the
		// server sent it TO — which is the client's (src_ip, src_port).
		if n < IPV4HdrLen+TCPHdrLen || buf[0]>>4 != 4 || buf[9] != IPProtoTCP {
			t.mux.Lock()
			t.mux.mismatch++
			t.mux.Unlock()
			continue
		}
		ihl := int(buf[0]&0x0F) * 4
		if ihl < IPV4HdrLen || n < ihl+TCPHdrLen {
			t.mux.Lock()
			t.mux.mismatch++
			t.mux.Unlock()
			continue
		}
		var k demuxKey
		copy(k.srcIP[:], buf[16:20])
		k.srcPort = uint16(buf[ihl+2])<<8 | uint16(buf[ihl+3])

		t.mu.RLock()
		box, ok := t.boxes[k]
		t.mu.RUnlock()
		if !ok {
			t.mux.Lock()
			t.mux.dropped++
			t.mux.Unlock()
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case box.ch <- pkt:
		default:
			// Bounded inbox; drop to keep the reader hot. Real TCBs
			// will retransmit if loss matters.
			t.mux.Lock()
			t.mux.dropped++
			t.mux.Unlock()
		}
	}
}

// Recv returns the next packet from the inbox, or ErrTimeout. Returns
// ErrClosed if the transport closed before a packet arrived.
func (i *Inbox) Recv(timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		select {
		case pkt, ok := <-i.ch:
			if !ok {
				return nil, ErrInboxClosed
			}
			return pkt, nil
		default:
			return nil, ErrTimeout
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case pkt, ok := <-i.ch:
		if !ok {
			return nil, ErrInboxClosed
		}
		return pkt, nil
	case <-timer.C:
		return nil, ErrTimeout
	}
}

// Close removes the inbox from the routing table and closes its channel.
func (i *Inbox) Close() {
	i.closeMu.Lock()
	defer i.closeMu.Unlock()
	if i.closed {
		return
	}
	i.closed = true
	if i.owner != nil {
		i.owner.mu.Lock()
		delete(i.owner.boxes, i.key)
		i.owner.mu.Unlock()
	}
	close(i.ch)
}

// closeNoUnregister is the variant called by Transport.Close when the
// caller already holds the table mutex.
func (i *Inbox) closeNoUnregister() {
	i.closeMu.Lock()
	defer i.closeMu.Unlock()
	if i.closed {
		return
	}
	i.closed = true
	close(i.ch)
}

// Sentinel errors.
var (
	ErrTimeout     = errors.New("wgserver transport: recv timeout")
	ErrInboxClosed = errors.New("wgserver transport: inbox closed")
)
