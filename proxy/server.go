/*
 * Copyright (C) 2019 The "MysteriumNetwork/openvpn-forwarder" Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	log "github.com/cihub/seelog"
	"github.com/inconshreveable/go-vhost"
	"github.com/pkg/errors"
	"github.com/soheilhy/cmux"
	netproxy "golang.org/x/net/proxy"
)

const (
	strHeaderBasicRealm = "Basic realm=\"\"\r\n\r\n"
)

type handlerMiddleware func(func(c *Context)) func(*Context)

type domainTracker interface {
	Inc(domain string)
}

type proxyServer struct {
	allowedSubnets    []*net.IPNet
	allowedIPs        []net.IP
	dialer            netproxy.Dialer
	sm                StickyMapper
	dt                domainTracker
	portMap           map[string]string
	handlerMiddleware handlerMiddleware
	parser            UsernameParser
	auth              Auth
	orchestrator      *Orchestra
	sessionStorage    *Sessions
}

// StickyMapper represent connection stickiness storage.
type StickyMapper interface {
	Save(ip, userID string)
	Hash(ip string) (hash string)
}

// NewServer returns new instance of HTTP transparent proxy server
func NewServer(
	allowedSubnets []*net.IPNet,
	allowedIPs []net.IP,
	upstreamDialer netproxy.Dialer,
	mapper StickyMapper,
	dt domainTracker,
	portMap map[string]string,
	handlerMiddleware handlerMiddleware,
	parser UsernameParser,
	auth Auth,
	orchestrator *Orchestra,
	sessionStorage *Sessions,
) *proxyServer {
	return &proxyServer{
		allowedSubnets:    allowedSubnets,
		allowedIPs:        allowedIPs,
		dialer:            upstreamDialer,
		sm:                mapper,
		dt:                dt,
		portMap:           portMap,
		handlerMiddleware: handlerMiddleware,
		parser:            parser,
		auth:              auth,
		orchestrator:      orchestrator,
		sessionStorage:    sessionStorage,
	}
}

// ListenAndServe starts proxy server.
func (s *proxyServer) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return errors.Wrap(err, "failed to listen http connections")
	}

	log.Infof("Serving HTTPS proxy on %s", ln.Addr().String())

	m := cmux.New(ln)
	httpsL := m.Match(cmux.TLS())
	httpL := m.Match(cmux.HTTP1Fast())

	go s.handler(httpL, s.serveHTTP, "http")
	go s.handler(httpsL, s.serveTLS, "https")

	return m.Serve()
}

func (s *proxyServer) handler(l net.Listener, f func(c *Context), scheme string) {
	if s.handlerMiddleware != nil {
		f = s.handlerMiddleware(f)
	}

	for {
		conn, err := l.Accept()
		c := Context{hostnameSet: make(chan struct{})}
		c.scheme = scheme
		c.conn = NewConn(conn, &c)

		connMux, ok := conn.(*cmux.MuxConn)
		if !ok {
			err = fmt.Errorf("unsupported connection: %T", conn)
		}
		connTCP, ok := connMux.Conn.(*net.TCPConn)
		if !ok {
			err = fmt.Errorf("non-TCP connection: %T", connMux.Conn)
		}
		// clientAddr, ok := connTCP.RemoteAddr().(*net.TCPAddr)
		if !ok {
			err = fmt.Errorf("non-TCP address: %T", connTCP.RemoteAddr())
		}
		if err != nil {
			s.logError(fmt.Sprintf("Error accepting new connection. %v", err), &c)
			continue
		}

		// clientAddrAllowed := false
		// for _, subnet := range s.allowedSubnets {
		// 	if subnet.Contains(clientAddr.IP) {
		// 		clientAddrAllowed = true
		// 		break
		// 	}
		// }
		// for _, ip := range s.allowedIPs {
		// 	if ip.Equal(clientAddr.IP) {
		// 		clientAddrAllowed = true
		// 		break
		// 	}
		// }
		// if !clientAddrAllowed {
		// 	s.logWarn(fmt.Sprintf("Access restricted from address %s", clientAddr.IP.String()), &c)
		// 	continue
		// }

		c.connOriginalDst, err = getOriginalDst(connTCP)
		if c.connOriginalDst.String() == c.conn.LocalAddr().String() {
			c.connOriginalDst = nil
		}

		go func() {
			f(&c)
			c.conn.Close()

			if c.connOriginalDst == nil {
				s.logWarn("Failure recovering original destination address. Are you redirecting from same host network?", &c)
			}
		}()
	}
}

func (s *proxyServer) serveHTTP(c *Context) {
	req, err := http.ReadRequest(bufio.NewReader(c.conn))
	if err != nil {
		s.logAccess(fmt.Sprintf("Failed to accept new HTTP request: %v", err), c)
		return
	}

	username, password, err := extractCredentials(req, req)
	fmt.Println("Username:", username)
	fmt.Println("Password:", password)
	if err != nil {
		// Set the response header and status code
		response := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"\"\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n"
		// Write the response to the connection
		c.conn.Write([]byte(response))
		return
	}

	request := acquireRequest()
	request.Done = make(chan struct{}, 1)
	// host, _, err := net.SplitHostPort(req.RemoteAddr)
	// if err != nil {
	// 	sendBadRequest(c.conn)
	// 	releaseRequest(request)
	// 	return
	// }

	// userIP := net.ParseIP(host)
	// if userIP == nil {
	// 	sendBadRequest(c.conn)
	// 	releaseRequest(request)
	// 	return
	// }
	// request.UserIP = userIP.String()

	err = parseRequest(req.Host, username, password, request, s.parser)
	if err != nil {
		sendBadRequest(c.conn)
		releaseRequest(request)
		return
	}

	// cleanRequestHeaders(req)
	err = s.selectProvider(request)
	if err != nil {
		sendBadRequest(c.conn)
		releaseRequest(request)
		return
	}

	c.setHost(req.Host)
	c.destinationAddress = s.authorityAddr("http", c.destinationHost)
	s.logAccess("HTTP request", c)

	conn, err := s.connectTo(c, c.destinationAddress, request)
	if err != nil {
		s.logError(fmt.Sprintf("Failed to establishing connection. %v", err), c)
		releaseRequest(request)
		return
	}
	defer conn.Close()

	if req.Method == http.MethodConnect {
		c.conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	} else if err := req.Write(conn); err != nil {
		s.logError(fmt.Sprintf("Failed to forward HTTP request. %v", err), c)
		releaseRequest(request)
		return
	}

	releaseRequest(request)
	go io.Copy(conn, c.conn)
	io.Copy(c.conn, conn)

}

func (p *proxyServer) selectProvider(request *Request) error {
	var err error

	if request.SessionID != "" {
		var ok bool
		request.Provider, ok = p.sessionStorage.Cached(request)
		if !ok {
			fmt.Println("Failed to cache session")
			request.Provider, ok = p.orchestrator.GetIdle(request)
			if !ok {
				return errors.New("failed to get provider")
			}

			request.Provider.SetBinded(true)
			err = p.sessionStorage.Start(request)
			if err != nil {
				return err
			}
		}

		return nil
	}

	var ok bool
	request.Provider, ok = p.orchestrator.GetIdle(request)
	if ok {
		request.Provider.SetBinded(true)
		return nil
	} else {
		return errors.New("failed to get provider")
	}

}

func sendBadRequest(conn net.Conn) {
	response := "HTTP/1.1 400 Bad Request\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	conn.Write([]byte(response))
}

func (s *proxyServer) authorityAddr(scheme, authority string) string {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		port = "443"
		if scheme == "http" {
			port = "80"
		}
		host = authority
	}

	if p, ok := s.portMap[port]; ok {
		port = p
	}
	return net.JoinHostPort(host, port)
}

func (s *proxyServer) serveTLS(c *Context) {
	defer func() {
		// For some malformed TLS connection vhost.TLS could panic.
		// We don't care about a single failed request, service should keep working.
		if r := recover(); r != nil {
			s.logError(fmt.Sprintf("Recovered panic in serveTLS. %v", r), c)
		}
	}()

	tlsConn, err := vhost.TLS(c.conn)
	if err != nil {
		s.logError(fmt.Sprintf("Failed to accept new TLS request. %v", err), c)
		return
	}
	defer tlsConn.Close()

	if tlsConn.Host() != "" {
		_, port, err := net.SplitHostPort(tlsConn.LocalAddr().String())
		if err != nil {
			s.logError("Cannot parse local address", c)
			return
		}

		c.setHost(tlsConn.Host() + ":" + port)
		c.destinationAddress = s.authorityAddr("https", c.destinationHost)
	} else if c.connOriginalDst != nil {
		c.setHost("")
		c.destinationAddress = c.connOriginalDst.String()
		s.logWarn("Cannon parse SNI in TLS request", c)
	} else {
		s.logError("Cannot support non-SNI enabled TLS sessions", c)
		return
	}
	s.logAccess("HTTPS request", c)

	conn, err := s.connectTo(c, c.destinationAddress, nil)
	if err != nil {
		s.logError(fmt.Sprintf("Failed to establishing connection. %v", err), c)
		return
	}
	defer conn.Close()

	go io.Copy(conn, tlsConn)
	io.Copy(tlsConn, conn)
}

func (s *proxyServer) connectTo(c *Context, remoteHost string, request *Request) (conn io.ReadWriteCloser, err error) {
	domain := strings.Split(remoteHost, ":")
	s.dt.Inc(domain[0])
	if request != nil {
		conn, err = request.Provider.Dialer().Dial("tcp", remoteHost)
	} else {
		conn, err = s.dialer.Dial("tcp", remoteHost)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to establish connection")
	}

	if proxyConnection, ok := conn.(*Connection); ok {
		clientHost, _, err := net.SplitHostPort(c.conn.RemoteAddr().String())
		if err != nil {
			return nil, errors.Wrap(err, "failed to get host from address")
		}
		if err := proxyConnection.ConnectTo(conn, remoteHost, s.sm.Hash(clientHost)); err != nil {
			return nil, errors.Wrap(err, "failed to establish CONNECT tunnel")
		}
	}

	return conn, nil
}

// SO_ORIGINAL_DST get the original destination for the socket when redirect by linux iptables
// refer to https://raw.githubusercontent.com/missdeer/avege/master/src/inbound/redir/redir_iptables.go
const SO_ORIGINAL_DST = 0x50

// getOriginalDst retrieves the original destination address from
// NATed connection.  Currently, only Linux iptables using DNAT/REDIRECT
// is supported.  For other operating systems, this will just return
// conn.LocalAddr().
//
// Note that this function only works when nf_conntrack_ipv4 and/or
// nf_conntrack_ipv6 is loaded in the kernel.
func getOriginalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	f, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fd := int(f.Fd())
	fmt.Println("fd:", runtime.GOOS)
	// if runtime.GOOS == "windows" {
	fmt.Println("Running on Windows")
	const (
		FIONBIO = 0x8004667E // Windows-specific ioctl for non-blocking
	)
	nonBlocking := byte(1)
	// revert to non-blocking mode.
	// see http://stackoverflow.com/a/28968431/1493661
	if err = syscall.WSAIoctl(
		syscall.Handle(fd),
		FIONBIO,
		&nonBlocking,
		4,
		nil,
		0,
		nil,
		nil,
		0,
	); err != nil {
		return nil, os.NewSyscallError("setnonblock", err)
	}

	// IPv4
	var addr syscall.RawSockaddrInet4
	var len int32
	len = int32(unsafe.Sizeof(addr))
	err = getSocketOptWindows(fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST, unsafe.Pointer(&addr), &len)
	if err != nil {
		return nil, os.NewSyscallError("getSockOpt", err)
	}

	ip := make([]byte, 4)
	for i, b := range addr.Addr {
		ip[i] = b
	}
	pb := *(*[2]byte)(unsafe.Pointer(&addr.Port))

	return &net.TCPAddr{
		IP:   ip,
		Port: int(pb[0])*256 + int(pb[1]),
	}, nil
	// }
	// Windows-specific code here
	// } else {
	//     fmt.Println("Running on Linux")
	// 	if err = syscall.SetNonblock(fd, true); err != nil {
	// 		return nil, os.NewSyscallError("setnonblock", err)
	// 	}

	// 	// IPv4
	// 	var addr syscall.RawSockaddrInet4
	// 	var len uint32
	// 	len = uint32(unsafe.Sizeof(addr))
	// 	err = getSockOpt(fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST, unsafe.Pointer(&addr), &len)
	// 	if err != nil {
	// 		return nil, os.NewSyscallError("getSockOpt", err)
	// 	}

	// 	ip := make([]byte, 4)
	// 	for i, b := range addr.Addr {
	// 		ip[i] = b
	// 	}
	// 	pb := *(*[2]byte)(unsafe.Pointer(&addr.Port))

	// 	return &net.TCPAddr{
	// 		IP:   ip,
	// 		Port: int(pb[0])*256 + int(pb[1]),
	// 	}, nil
	//     // Linux-specific code here
	// }
	// revert to non-blocking mode.
	// see http://stackoverflow.com/a/28968431/1493661

}

// func getSockOpt(s int, level int, optname int, optval unsafe.Pointer, optlen *uint32) (err error) {

// 	_, _, e := syscall.Syscall6(
// 		syscall.SYS_GETSOCKOPT,
// 		uintptr(s),
// 		uintptr(level),
// 		uintptr(optname),
// 		uintptr(optval),
// 		uintptr(unsafe.Pointer(optlen)),
// 		0,
// 	)
// 	if e != 0 {
// 		return e
// 	}
// 	return
// }

func getSocketOptWindows(
	socket int,
	level,
	optname int,
	optval unsafe.Pointer,
	optlen *int32,
) error {
	// Windows uses a different syscall mechanism
	h := syscall.Handle(socket)
	err := syscall.Getsockopt(h, int32(level), int32(optname), (*byte)(optval), optlen)
	if err != nil {
		return fmt.Errorf("windows getsockopt error: %v", err)
	}
	return nil
}

func (s *proxyServer) logAccess(message string, c *Context) {
	log.Tracef(
		"%s [client_addr=%s, dest_addr=%s, original_dest_addr=%s destination_host=%s, destination_addr=%s]",
		message,
		c.conn.RemoteAddr().String(),
		c.conn.LocalAddr().String(),
		c.connOriginalDst.String(),
		c.destinationHost,
		c.destinationAddress,
	)
}

func (s *proxyServer) logError(message string, c *Context) {
	_ = log.Errorf(
		"%s [client_addr=%s, dest_addr=%s, original_dest_addr=%s destination_host=%s, destination_addr=%s]",
		message,
		c.conn.RemoteAddr().String(),
		c.conn.LocalAddr().String(),
		c.connOriginalDst.String(),
		c.destinationHost,
		c.destinationAddress,
	)
}

func (s *proxyServer) logWarn(message string, c *Context) {
	_ = log.Warnf(
		"%s [client_addr=%s, dest_addr=%s, original_dest_addr=%s destination_host=%s, destination_addr=%s]",
		message,
		c.conn.RemoteAddr().String(),
		c.conn.LocalAddr().String(),
		c.connOriginalDst.String(),
		c.destinationHost,
		c.destinationAddress,
	)
}
