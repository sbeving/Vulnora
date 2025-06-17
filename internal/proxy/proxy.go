package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"vulnora/internal/core"
)

// Proxy represents the HTTP/HTTPS proxy server
type Proxy struct {
	config          *core.ProxyConfig
	logger          *logrus.Logger
	interceptor     *Interceptor
	certificate     *CertificateManager
	server          *http.Server
	tlsServer       *http.Server
	sessions        map[string]*core.Session
	sessionsMutex   sync.RWMutex
	middleware      []MiddlewareFunc
	running         bool
	runningMutex    sync.RWMutex
	stats           ProxyStats
	statsMutex      sync.RWMutex
}

// ProxyStats holds proxy statistics
type ProxyStats struct {
	RequestsHandled   int64     `json:"requests_handled"`
	ConnectionsActive int64     `json:"connections_active"`
	DataTransferred   int64     `json:"data_transferred"`
	ErrorsCount       int64     `json:"errors_count"`
	StartTime         time.Time `json:"start_time"`
	LastRequestTime   time.Time `json:"last_request_time"`
}

// MiddlewareFunc defines the middleware function signature
type MiddlewareFunc func(http.ResponseWriter, *http.Request, http.HandlerFunc)

// NewProxy creates a new proxy instance
func NewProxy(config *core.ProxyConfig, logger *logrus.Logger) (*Proxy, error) {
	interceptor := NewInterceptor(logger)
	certManager, err := NewCertificateManager(config.CertFile, config.KeyFile, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate manager: %w", err)
	}

	proxy := &Proxy{
		config:      config,
		logger:      logger,
		interceptor: interceptor,
		certificate: certManager,
		sessions:    make(map[string]*core.Session),
		middleware:  []MiddlewareFunc{},
		stats: ProxyStats{
			StartTime: time.Now(),
		},
	}

	// Setup HTTP server
	proxy.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.Host, config.Port),
		Handler:      proxy,
		ReadTimeout:  time.Duration(config.RequestTimeout) * time.Second,
		WriteTimeout: time.Duration(config.ResponseTimeout) * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Setup HTTPS server if TLS is configured
	if config.CertFile != "" && config.KeyFile != "" {
		tlsConfig := &tls.Config{
			GetCertificate: certManager.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		}

		proxy.tlsServer = &http.Server{
			Addr:         fmt.Sprintf("%s:%d", config.Host, config.TLSPort),
			Handler:      proxy,
			TLSConfig:    tlsConfig,
			ReadTimeout:  time.Duration(config.RequestTimeout) * time.Second,
			WriteTimeout: time.Duration(config.ResponseTimeout) * time.Second,
			IdleTimeout:  60 * time.Second,
		}
	}

	return proxy, nil
}

// Start starts the proxy server
func (p *Proxy) Start(ctx context.Context) error {
	p.runningMutex.Lock()
	defer p.runningMutex.Unlock()

	if p.running {
		return fmt.Errorf("proxy is already running")
	}

	errChan := make(chan error, 2)

	// Start HTTP server
	go func() {
		p.logger.Infof("Starting HTTP proxy server on %s", p.server.Addr)
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Start HTTPS server if configured
	if p.tlsServer != nil {
		go func() {
			p.logger.Infof("Starting HTTPS proxy server on %s", p.tlsServer.Addr)
			if err := p.tlsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("HTTPS server error: %w", err)
			}
		}()
	}

	p.running = true
	p.logger.Info("Proxy server started successfully")

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		return p.Stop()
	case err := <-errChan:
		p.running = false
		return err
	}
}

// Stop stops the proxy server
func (p *Proxy) Stop() error {
	p.runningMutex.Lock()
	defer p.runningMutex.Unlock()

	if !p.running {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var errors []string

	// Shutdown HTTP server
	if err := p.server.Shutdown(ctx); err != nil {
		errors = append(errors, fmt.Sprintf("HTTP server shutdown error: %v", err))
	}

	// Shutdown HTTPS server
	if p.tlsServer != nil {
		if err := p.tlsServer.Shutdown(ctx); err != nil {
			errors = append(errors, fmt.Sprintf("HTTPS server shutdown error: %v", err))
		}
	}

	p.running = false
	p.logger.Info("Proxy server stopped")

	if len(errors) > 0 {
		return fmt.Errorf("shutdown errors: %s", strings.Join(errors, ", "))
	}

	return nil
}

// ServeHTTP implements the http.Handler interface
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.updateStats(func(stats *ProxyStats) {
		stats.RequestsHandled++
		stats.LastRequestTime = time.Now()
		stats.ConnectionsActive++
	})

	defer p.updateStats(func(stats *ProxyStats) {
		stats.ConnectionsActive--
	})

	// Apply middleware
	handler := http.HandlerFunc(p.handleRequest)
	for i := len(p.middleware) - 1; i >= 0; i-- {
		middleware := p.middleware[i]
		next := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			middleware(w, r, next)
		})
	}

	handler.ServeHTTP(w, r)
}

// handleRequest handles incoming HTTP requests
func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Check if host is allowed
	if !p.isHostAllowed(r.Host) {
		http.Error(w, "Host not allowed", http.StatusForbidden)
		return
	}

	// Check if host is blocked
	if p.isHostBlocked(r.Host) {
		http.Error(w, "Host blocked", http.StatusForbidden)
		return
	}

	// Handle CONNECT method for HTTPS tunneling
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	// Handle regular HTTP requests
	p.handleHTTP(w, r)
}

// handleHTTP handles regular HTTP requests
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionID(r)
	
	// Intercept request
	intercepted, modified := p.interceptor.InterceptRequest(r, sessionID)
	if intercepted && !modified {
		// Request was blocked
		http.Error(w, "Request blocked by interceptor", http.StatusForbidden)
		return
	}

	// Create HTTP client with proxy configuration
	client := p.createHTTPClient()

	// Forward the request
	resp, err := client.Do(r)
	if err != nil {
		p.logger.Errorf("Error forwarding request: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		p.updateStats(func(stats *ProxyStats) {
			stats.ErrorsCount++
		})
		return
	}
	defer resp.Body.Close()

	// Intercept response
	intercepted, modified = p.interceptor.InterceptResponse(resp, sessionID)
	if intercepted && !modified {
		// Response was blocked
		http.Error(w, "Response blocked by interceptor", http.StatusForbidden)
		return
	}

	// Copy response headers
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	// Copy response body and track data transfer
	written, err := io.Copy(w, resp.Body)
	if err != nil {
		p.logger.Errorf("Error copying response body: %v", err)
		return
	}

	p.updateStats(func(stats *ProxyStats) {
		stats.DataTransferred += written
	})
}

// handleConnect handles HTTPS CONNECT requests
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Parse target host and port
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		if !strings.Contains(err.Error(), "missing port") {
			http.Error(w, "Invalid host", http.StatusBadRequest)
			return
		}
		host = r.Host
		port = "443"
	}

	// Connect to target server
	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		http.Error(w, "Cannot connect to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijacking failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Send 200 Connection Established
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	// If we have TLS interception enabled, handle it
	if p.certificate != nil && p.shouldInterceptTLS(host) {
		p.handleTLSInterception(clientConn, targetConn, host)
	} else {
		// Plain tunneling
		p.tunnel(clientConn, targetConn)
	}
}

// handleTLSInterception handles TLS interception for HTTPS traffic
func (p *Proxy) handleTLSInterception(clientConn, targetConn net.Conn, host string) {
	// Create TLS config for client connection
	cert, err := p.certificate.GetCertificateForHost(host)
	if err != nil {
		p.logger.Errorf("Failed to get certificate for %s: %v", host, err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ServerName:   host,
	}

	// Wrap client connection with TLS
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		p.logger.Errorf("TLS handshake failed: %v", err)
		return
	}

	// Create TLS connection to target
	tlsTargetConn := tls.Client(targetConn, &tls.Config{
		ServerName: host,
	})

	// Handle intercepted HTTPS traffic
	p.handleInterceptedHTTPS(tlsClientConn, tlsTargetConn, host)
}

// handleInterceptedHTTPS handles intercepted HTTPS traffic
func (p *Proxy) handleInterceptedHTTPS(clientConn, targetConn *tls.Conn, host string) {
	// Read HTTP request from client
	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		p.logger.Errorf("Failed to read HTTPS request: %v", err)
		return
	}

	// Set proper URL for the request
	req.URL.Scheme = "https"
	req.URL.Host = host

	sessionID := p.getSessionID(req)

	// Intercept request
	intercepted, modified := p.interceptor.InterceptRequest(req, sessionID)
	if intercepted && !modified {
		// Send error response
		resp := &http.Response{
			Status:     "403 Forbidden",
			StatusCode: 403,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("Request blocked")),
		}
		resp.Write(clientConn)
		return
	}

	// Forward request to target
	if err := req.Write(targetConn); err != nil {
		p.logger.Errorf("Failed to forward HTTPS request: %v", err)
		return
	}

	// Read response from target
	targetReader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(targetReader, req)
	if err != nil {
		p.logger.Errorf("Failed to read HTTPS response: %v", err)
		return
	}

	// Intercept response
	intercepted, modified = p.interceptor.InterceptResponse(resp, sessionID)
	if intercepted && !modified {
		// Send error response
		errorResp := &http.Response{
			Status:     "403 Forbidden",
			StatusCode: 403,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("Response blocked")),
		}
		errorResp.Write(clientConn)
		return
	}

	// Forward response to client
	if err := resp.Write(clientConn); err != nil {
		p.logger.Errorf("Failed to forward HTTPS response: %v", err)
		return
	}
}

// tunnel creates a bidirectional tunnel between two connections
func (p *Proxy) tunnel(conn1, conn2 net.Conn) {
	done := make(chan struct{}, 2)

	// Copy data from conn1 to conn2
	go func() {
		defer func() { done <- struct{}{} }()
		written, err := io.Copy(conn2, conn1)
		if err != nil {
			p.logger.Debugf("Tunnel copy error (conn1->conn2): %v", err)
		}
		p.updateStats(func(stats *ProxyStats) {
			stats.DataTransferred += written
		})
	}()

	// Copy data from conn2 to conn1
	go func() {
		defer func() { done <- struct{}{} }()
		written, err := io.Copy(conn1, conn2)
		if err != nil {
			p.logger.Debugf("Tunnel copy error (conn2->conn1): %v", err)
		}
		p.updateStats(func(stats *ProxyStats) {
			stats.DataTransferred += written
		})
	}()

	// Wait for one direction to close
	<-done
}

// createHTTPClient creates an HTTP client with proxy configuration
func (p *Proxy) createHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Configure upstream proxy if specified
	if p.config.UpstreamProxy != "" {
		proxyURL, err := url.Parse(p.config.UpstreamProxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(p.config.RequestTimeout) * time.Second,
	}
}

// isHostAllowed checks if a host is in the allowed list
func (p *Proxy) isHostAllowed(host string) bool {
	if len(p.config.AllowedHosts) == 0 {
		return true // Allow all if no restrictions
	}

	for _, allowed := range p.config.AllowedHosts {
		if strings.Contains(host, allowed) {
			return true
		}
	}
	return false
}

// isHostBlocked checks if a host is in the blocked list
func (p *Proxy) isHostBlocked(host string) bool {
	for _, blocked := range p.config.BlockedHosts {
		if strings.Contains(host, blocked) {
			return true
		}
	}
	return false
}

// shouldInterceptTLS determines if TLS should be intercepted for a host
func (p *Proxy) shouldInterceptTLS(host string) bool {
	// For now, intercept all HTTPS traffic
	// This could be made configurable
	return true
}

// getSessionID extracts or creates a session ID for the request
func (p *Proxy) getSessionID(r *http.Request) string {
	// Try to get session ID from header
	if sessionID := r.Header.Get("X-Vulnora-Session"); sessionID != "" {
		return sessionID
	}

	// Use default session
	return "default"
}

// updateStats safely updates proxy statistics
func (p *Proxy) updateStats(updateFunc func(*ProxyStats)) {
	p.statsMutex.Lock()
	defer p.statsMutex.Unlock()
	updateFunc(&p.stats)
}

// GetStats returns current proxy statistics
func (p *Proxy) GetStats() ProxyStats {
	p.statsMutex.RLock()
	defer p.statsMutex.RUnlock()
	return p.stats
}

// AddMiddleware adds a middleware function to the proxy
func (p *Proxy) AddMiddleware(middleware MiddlewareFunc) {
	p.middleware = append(p.middleware, middleware)
}

// GetInterceptor returns the request/response interceptor
func (p *Proxy) GetInterceptor() *Interceptor {
	return p.interceptor
}

// IsRunning returns whether the proxy is currently running
func (p *Proxy) IsRunning() bool {
	p.runningMutex.RLock()
	defer p.runningMutex.RUnlock()
	return p.running
}
