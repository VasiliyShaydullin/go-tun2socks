package udpgw

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/vasiliyshaydullin/go-tun2socks/common/log"
	"github.com/vasiliyshaydullin/go-tun2socks/core"
)

type udpGwHandler struct {
	sync.Mutex

	proxyHost   string
	proxyPort   uint16
	udpConns    map[core.UDPConn]net.PacketConn
	tcpConns    map[core.UDPConn]net.Conn
	remoteAddrs map[core.UDPConn]*net.UDPAddr
	connIDs     map[core.UDPConn]uint16
	timeout     time.Duration
}

func NewUDPGWHandler(proxyHost string, proxyPort uint16, timeout time.Duration) core.UDPConnHandler {
	rand.Seed(time.Now().UnixNano())
	return &udpGwHandler{
		proxyHost:   proxyHost,
		proxyPort:   proxyPort,
		udpConns:    make(map[core.UDPConn]net.PacketConn, 8),
		tcpConns:    make(map[core.UDPConn]net.Conn, 8),
		remoteAddrs: make(map[core.UDPConn]*net.UDPAddr, 8),
		connIDs:     make(map[core.UDPConn]uint16, 8),
		timeout:     timeout,
	}
}

func (h *udpGwHandler) fetchUDPInput(conn core.UDPConn, input net.PacketConn, raddr *net.UDPAddr) {
	defer h.Close(conn)
	buf := make([]byte, 64*1024)
	for {
		n, _, err := input.ReadFrom(buf)
		if err != nil {
			if err != io.EOF {
				log.Errorf("fetchUDPInput read error: %v", err)
			}
			return
		}
		if n < 3 || buf[0] != 0x02 {
			continue // not a data packet
		}

		recvID := uint16(buf[1])<<8 | uint16(buf[2])

		h.Lock()
		savedID, ok := h.connIDs[conn]
		if !ok || recvID != savedID {
			h.Unlock()
			continue
		}
		if raddr != nil {
			h.remoteAddrs[conn] = raddr
		}
		addrToSend := h.remoteAddrs[conn]
		h.Unlock()

		if addrToSend != nil {
			_, err = conn.WriteFrom(buf[3:n], addrToSend)
			if err != nil {
				log.Errorf("WriteFrom error: %v", err)
				return
			}
		}
	}
}

func (h *udpGwHandler) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	if target == nil {
		return h.connectInternal(conn, "")
	}
	return h.connectInternal(conn, target.String())
}

func (h *udpGwHandler) connectInternal(conn core.UDPConn, dest string) error {
	udpServerAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", h.proxyHost, h.proxyPort))
	if err != nil {
		return err
	}

	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}

	var raddr *net.UDPAddr
	if dest != "" {
		raddr, err = net.ResolveUDPAddr("udp", dest)
		if err != nil {
			pc.Close()
			return err
		}
	}

	h.Lock()
	h.udpConns[conn] = pc
	h.remoteAddrs[conn] = udpServerAddr
	connID := uint16(rand.Intn(0xffff))
	h.connIDs[conn] = connID
	h.Unlock()

	if raddr != nil {
		var addrType byte
		var addrBytes []byte
		var portBytes [2]byte

		if ip4 := raddr.IP.To4(); ip4 != nil {
			addrType = 0x01
			addrBytes = ip4
		} else if ip6 := raddr.IP.To16(); ip6 != nil {
			addrType = 0x04
			addrBytes = ip6
		} else {
			pc.Close()
			return fmt.Errorf("unsupported address type: %v", raddr.IP)
		}

		portBytes[0] = byte(raddr.Port >> 8)
		portBytes[1] = byte(raddr.Port & 0xff)

		buf := make([]byte, 4+len(addrBytes)+2)
		buf[0] = 0x01
		buf[1] = byte(connID >> 8)
		buf[2] = byte(connID & 0xff)
		buf[3] = addrType
		copy(buf[4:], addrBytes)
		copy(buf[4+len(addrBytes):], portBytes[:])

		_, err = pc.WriteTo(buf, udpServerAddr)
		if err != nil {
			pc.Close()
			return fmt.Errorf("connect failed: %v", err)
		}
	}

	go h.fetchUDPInput(conn, pc, raddr)

	log.Infof("connected to udpgw %s for %s (id %d)", udpServerAddr, dest, connID)
	return nil
}

func (h *udpGwHandler) ReceiveTo(conn core.UDPConn, data []byte, addr *net.UDPAddr) error {
	h.Lock()
	pc, ok1 := h.udpConns[conn]
	remoteAddr, ok2 := h.remoteAddrs[conn]
	h.Unlock()

	if !ok1 || !ok2 {
		h.Close(conn)
		return fmt.Errorf("proxy connection %v->%v does not exist", conn.LocalAddr(), addr)
	}

	// Get a connection ID (например, порт клиента)
	connID := uint16(conn.LocalAddr().Port)

	// Соберём буфер для команды 0x02 (send data)
	buf := make([]byte, 3+len(data))
	buf[0] = 0x02
	buf[1] = byte(connID >> 8)
	buf[2] = byte(connID & 0xff)
	copy(buf[3:], data)

	_, err := pc.WriteTo(buf, remoteAddr)
	if err != nil {
		h.Close(conn)
		return fmt.Errorf("write remote failed: %v", err)
	}

	return nil
}

func (h *udpGwHandler) Close(conn core.UDPConn) {
	conn.Close()

	h.Lock()
	defer h.Unlock()

	if c, ok := h.tcpConns[conn]; ok {
		c.Close()
		delete(h.tcpConns, conn)
	}
	if pc, ok := h.udpConns[conn]; ok {
		pc.Close()
		delete(h.udpConns, conn)
	}
	delete(h.remoteAddrs, conn)
}
