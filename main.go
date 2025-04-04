package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type Proxy struct {
	// Configuration options
	AllowedHosts []string
	Verbose      bool
}

func (p *Proxy) log(message string) {
	if p.Verbose {
		log.Println("[PROXY]", message)
	}
}

func (p *Proxy) isHostAllowed(host string) bool {
	if len(p.AllowedHosts) == 0 {
		return true
	}

	for _, allowed := range p.AllowedHosts {
		if strings.Contains(host, allowed) {
			return true
		}
	}
	return false
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Log the request
	p.log(fmt.Sprintf("Received request: %s %s", r.Method, r.URL))

	// Check if CONNECT method (HTTPS tunneling)
	if r.Method == http.MethodConnect {
		p.handleHttpsTunnel(w, r)
		return
	}

	// Handle regular HTTP proxy request
	p.handleHttpProxy(w, r)
}

func (p *Proxy) handleHttpProxy(w http.ResponseWriter, r *http.Request) {
	// Validate host
	if !p.isHostAllowed(r.Host) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	// Remove proxy-specific headers
	r.RequestURI = ""

	// Create a new client
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Disable automatic redirects
		},
	}

	// Forward the request
	resp, err := client.Do(r)
	if err != nil {
		p.log(fmt.Sprintf("Proxy request error: %v", err))
		http.Error(w, "Proxy Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	io.Copy(w, resp.Body)
}

func (p *Proxy) handleHttpsTunnel(w http.ResponseWriter, r *http.Request) {
	// Extract destination host
	host := r.Host

	// Validate host
	if !p.isHostAllowed(host) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	p.log(fmt.Sprintf("CONNECT request to: %s", host))

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	// Get the client connection
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Establish connection to the destination
	serverConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		p.log(fmt.Sprintf("Connection error: %v", err))
		clientConn.Write([]byte("HTTP/1.1 500 Connection Failed\r\n\r\n"))
		return
	}
	defer serverConn.Close()

	// Send successful connection response
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Create bidirectional tunnel
	errChan := make(chan error, 2)

	// Client to server
	go func() {
		_, err := io.Copy(serverConn, clientConn)
		errChan <- err
	}()

	// Server to client
	go func() {
		_, err := io.Copy(clientConn, serverConn)
		errChan <- err
	}()

	// Wait for first error or completion
	<-errChan
}

func main() {
	proxy := &Proxy{
		AllowedHosts: []string{
			"api.ipify.org",
			"example.com",
			"github.com",
		},
		Verbose: true,
	}

	// Create server
	server := &http.Server{
		Addr:         ":8090",
		Handler:      proxy,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Println("Proxy server starting on :8080")
	log.Fatal(server.ListenAndServe())
}
