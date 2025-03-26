// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/stun/v3"
)

// ErrGetTransportAddress can't convert net.Addr to underlying type (UDPAddr or TCPAddr).
var ErrGetTransportAddress = errors.New("failed to get local transport address")

// TCPMux is allows grouping multiple TCP net.Conns and using them like UDP
// net.PacketConns. The main implementation of this is TCPMuxDefault, and this
// interface exists to allow mocking in tests.
type TCPMux interface {
	io.Closer
	GetConnByUfrag(ufrag string, isIPv6 bool, local net.IP) (net.PacketConn, error)
	RemoveConnByUfrag(ufrag string)
}

type ipAddr string

// TCPMuxDefault muxes TCP net.Conns into net.PacketConns and groups them by
// Ufrag. It is a default implementation of TCPMux interface.
type TCPMuxDefault struct {
	params *TCPMuxParams
	closed bool

	// conns is a map of all tcpPacketConns indexed by ufrag
	conns map[string]*tcpPacketConn

	mu sync.Mutex
	wg sync.WaitGroup
}

// TCPMuxParams are parameters for TCPMux.
type TCPMuxParams struct {
	Listener       net.Listener
	Logger         logging.LeveledLogger
	ReadBufferSize int

	// Maximum buffer size for write op. 0 means no write buffer, the write op will block until the whole packet is written
	// if the write buffer is full, the subsequent write packet will be dropped until it has enough space.
	// a default 4MB is recommended.
	WriteBufferSize int

	// A new established connection will be removed if the first STUN binding request is not received within this timeout,
	// avoiding the client with bad network or attacker to create a lot of empty connections.
	// Default 30s timeout will be used if not set.
	FirstStunBindTimeout time.Duration

	// TCPMux will create connection from STUN binding request with an unknown username, if
	// the connection is not used in the timeout, it will be removed to avoid resource leak / attack.
	// Default 30s timeout will be used if not set.
	AliveDurationForConnFromStun time.Duration
}

// NewTCPMuxDefault creates a new instance of TCPMuxDefault.
func NewTCPMuxDefault(params TCPMuxParams) *TCPMuxDefault {
	if params.Logger == nil {
		params.Logger = logging.NewDefaultLoggerFactory().NewLogger("ice")
	}

	if params.FirstStunBindTimeout == 0 {
		params.FirstStunBindTimeout = 30 * time.Second
	}

	if params.AliveDurationForConnFromStun == 0 {
		params.AliveDurationForConnFromStun = 30 * time.Second
	}

	mux := &TCPMuxDefault{
		params: &params,

		conns: map[string]*tcpPacketConn{},
	}

	mux.wg.Add(1)
	go func() {
		defer mux.wg.Done()
		mux.start()
	}()

	return mux
}

func (m *TCPMuxDefault) start() {
	m.params.Logger.Infof("Listening TCP on %s", m.params.Listener.Addr())
	for {
		conn, err := m.params.Listener.Accept()
		if err != nil {
			m.params.Logger.Infof("Error accepting connection: %s", err)

			return
		}

		m.params.Logger.Debugf("Accepted connection from: %s to %s", conn.RemoteAddr(), conn.LocalAddr())

		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.handleConn(conn)
		}()
	}
}

// LocalAddr returns the listening address of this TCPMuxDefault.
func (m *TCPMuxDefault) LocalAddr() net.Addr {
	return m.params.Listener.Addr()
}

// GetConnByUfrag retrieves an existing or creates a new net.PacketConn.
func (m *TCPMuxDefault) GetConnByUfrag(ufrag string, isIPv6 bool, local net.IP) (net.PacketConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, io.ErrClosedPipe
	}

	if conn, ok := m.getConn(ufrag); ok {
		conn.ClearAliveTimer()

		return conn, nil
	}

	return m.createConn(ufrag, false)
}

func (m *TCPMuxDefault) createConn(ufrag string, fromStun bool) (*tcpPacketConn, error) {
	var alive time.Duration
	if fromStun {
		alive = m.params.AliveDurationForConnFromStun
	}

	conn := newTCPPacketConn(tcpPacketParams{
		ReadBuffer:    m.params.ReadBufferSize,
		WriteBuffer:   m.params.WriteBufferSize,
		LocalAddr:     m.LocalAddr(),
		Logger:        m.params.Logger,
		AliveDuration: alive,
	})

	if _, ok := m.conns[ufrag]; ok {
		panic("should not happen")
	}

	m.conns[ufrag] = conn

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		<-conn.CloseChannel()
		m.RemoveConnByUfrag(ufrag)
	}()

	return conn, nil
}

func (m *TCPMuxDefault) closeAndLogError(closer io.Closer) {
	err := closer.Close()
	if err != nil {
		m.params.Logger.Warnf("Error closing connection: %s", err)
	}
}

func (m *TCPMuxDefault) handleConn(conn net.Conn) { //nolint:cyclop
	buf := make([]byte, 512)

	if m.params.FirstStunBindTimeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(m.params.FirstStunBindTimeout)); err != nil {
			m.params.Logger.Warnf(
				"Failed to set read deadline for first STUN message: %s to %s , err: %s",
				conn.RemoteAddr(),
				conn.LocalAddr(),
				err,
			)
		}
	}
	n, err := readStreamingPacket(conn, buf)
	if err != nil {
		if errors.Is(err, io.ErrShortBuffer) {
			m.params.Logger.Warnf("Buffer too small for first packet from %s: %s", conn.RemoteAddr(), err)
		} else {
			m.params.Logger.Warnf("Error reading first packet from %s: %s", conn.RemoteAddr(), err)
		}
		m.closeAndLogError(conn)

		return
	}
	if err = conn.SetReadDeadline(time.Time{}); err != nil {
		m.params.Logger.Warnf("Failed to reset read deadline from %s: %s", conn.RemoteAddr(), err)
	}

	buf = buf[:n]

	msg := &stun.Message{
		Raw: make([]byte, len(buf)),
	}
	// Explicitly copy raw buffer so Message can own the memory.
	copy(msg.Raw, buf)
	if err = msg.Decode(); err != nil {
		m.closeAndLogError(conn)
		m.params.Logger.Warnf("Failed to handle decode ICE from %s to %s: %v", conn.RemoteAddr(), conn.LocalAddr(), err)

		return
	}

	if m == nil || msg.Type.Method != stun.MethodBinding { // Not a STUN
		m.closeAndLogError(conn)
		m.params.Logger.Warnf("Not a STUN message from %s to %s", conn.RemoteAddr(), conn.LocalAddr())

		return
	}

	for _, attr := range msg.Attributes {
		m.params.Logger.Debugf("Message attribute: %s", attr.String())
	}

	attr, err := msg.Get(stun.AttrUsername)
	if err != nil {
		m.closeAndLogError(conn)
		m.params.Logger.Warnf(
			"No Username attribute in STUN message from %s to %s",
			conn.RemoteAddr(),
			conn.LocalAddr(),
		)

		return
	}

	ufrag := strings.Split(string(attr), ":")[0]
	m.params.Logger.Debugf("Ufrag: %s", ufrag)

	m.mu.Lock()

	packetConn, ok := m.getConn(ufrag)
	if !ok {
		packetConn, err = m.createConn(ufrag, true)
		if err != nil {
			m.mu.Unlock()
			m.closeAndLogError(conn)
			m.params.Logger.Warnf(
				"Failed to create packetConn for STUN message from %s to %s",
				conn.RemoteAddr(),
				conn.LocalAddr(),
			)

			return
		}
	}
	m.mu.Unlock()

	if err := packetConn.AddConn(conn, buf); err != nil {
		m.closeAndLogError(conn)
		m.params.Logger.Warnf(
			"Error adding conn to tcpPacketConn from %s to %s: %s",
			conn.RemoteAddr(),
			conn.LocalAddr(),
			err,
		)

		return
	}
}

// Close closes the listener and waits for all goroutines to exit.
func (m *TCPMuxDefault) Close() error {
	m.mu.Lock()
	m.closed = true

	for _, conn := range m.conns {
		m.closeAndLogError(conn)
	}

	m.conns = map[string]*tcpPacketConn{}

	err := m.params.Listener.Close()

	m.mu.Unlock()

	m.wg.Wait()

	return err
}

// RemoveConnByUfrag closes and removes a net.PacketConn by Ufrag.
func (m *TCPMuxDefault) RemoveConnByUfrag(ufrag string) {
	removedConns := make([]*tcpPacketConn, 0, 4)

	// Keep lock section small to avoid deadlock with conn lock
	m.mu.Lock()
	if conn, ok := m.conns[ufrag]; ok {
		removedConns = append(removedConns, conn)
		delete(m.conns, ufrag)

	}

	m.mu.Unlock()

	// Close the connections outside the critical section to avoid
	// deadlocking TCP mux if (*tcpPacketConn).Close() blocks.
	for _, conn := range removedConns {
		m.closeAndLogError(conn)
	}
}

func (m *TCPMuxDefault) getConn(ufrag string) (val *tcpPacketConn, ok bool) {
	c, ok := m.conns[ufrag]
	return c, ok
}

const streamingPacketHeaderLen = 2

// readStreamingPacket reads 1 packet from stream
// read packet  bytes https://tools.ietf.org/html/rfc4571#section-2
// 2-byte length header prepends each packet:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	-----------------------------------------------------------------
//	|             LENGTH            |  RTP or RTCP packet ...       |
//	-----------------------------------------------------------------
func readStreamingPacket(conn net.Conn, buf []byte) (int, error) {
	header := make([]byte, streamingPacketHeaderLen)
	var bytesRead, n int
	var err error

	for bytesRead < streamingPacketHeaderLen {
		if n, err = conn.Read(header[bytesRead:streamingPacketHeaderLen]); err != nil {
			return 0, err
		}
		bytesRead += n
	}

	length := int(binary.BigEndian.Uint16(header))

	if length > cap(buf) {
		return length, io.ErrShortBuffer
	}

	bytesRead = 0
	for bytesRead < length {
		if n, err = conn.Read(buf[bytesRead:length]); err != nil {
			return 0, err
		}
		bytesRead += n
	}

	return bytesRead, nil
}

func writeStreamingPacket(conn net.Conn, buf []byte) (int, error) {
	bufCopy := make([]byte, streamingPacketHeaderLen+len(buf))
	binary.BigEndian.PutUint16(bufCopy, uint16(len(buf))) //nolint:gosec // G115
	copy(bufCopy[2:], buf)

	n, err := conn.Write(bufCopy)
	if err != nil {
		return 0, err
	}

	return n - streamingPacketHeaderLen, nil
}
