package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// SOCKS5 constants
const (
	socks5Version = 0x05
	socks5AuthNone = 0x00
	socks5CmdConnect = 0x01
	socks5AddrIPv4 = 0x01
	socks5AddrDomain = 0x03
	socks5AddrIPv6 = 0x04
)

// HandleSocks5 performs the SOCKS5 handshake and returns the target address.
func HandleSocks5(conn net.Conn) (string, error) {
	// 1. Version and Methods
	buf := make([]byte, 256)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", err
	}
	if buf[0] != socks5Version {
		return "", fmt.Errorf("invalid SOCKS version: %d", buf[0])
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return "", err
	}

	// 2. Select Method (None)
	if _, err := conn.Write([]byte{socks5Version, socks5AuthNone}); err != nil {
		return "", err
	}

	// 3. Request
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return "", err
	}
	if buf[0] != socks5Version {
		return "", fmt.Errorf("invalid SOCKS version: %d", buf[0])
	}
	if buf[1] != socks5CmdConnect {
		return "", fmt.Errorf("unsupported command: %d", buf[1])
	}

	var host string
	switch buf[3] {
	case socks5AddrIPv4:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return "", err
		}
		host = net.IP(buf[:4]).String()
	case socks5AddrDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", err
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return "", err
		}
		host = string(buf[:domainLen])
	case socks5AddrIPv6:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return "", err
		}
		host = net.IP(buf[:16]).String()
	default:
		return "", fmt.Errorf("unsupported address type: %d", buf[3])
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(buf[:2])
	target := fmt.Sprintf("%s:%d", host, port)

	// 4. Reply (Success)
	// BND.ADDR and BND.PORT are usually zeros
	reply := []byte{socks5Version, 0x00, 0x00, socks5AddrIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		return "", err
	}

	return target, nil
}
