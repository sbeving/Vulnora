package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
	"vulnora/internal/core"
	"github.com/sirupsen/logrus"
)

// CertificateManager handles TLS certificate generation and management
type CertificateManager struct {
	config      *core.ProxyConfig
	logger      *logrus.Logger
	caCert      *x509.Certificate
	caKey       *rsa.PrivateKey
	certificates map[string]*tls.Certificate
	mutex       sync.RWMutex
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(config *core.ProxyConfig, logger *logrus.Logger) (*CertificateManager, error) {
	cm := &CertificateManager{
		config:       config,
		logger:       logger,
		certificates: make(map[string]*tls.Certificate),
	}

	// Initialize CA certificate and key
	if err := cm.initializeCA(); err != nil {
		return nil, fmt.Errorf("failed to initialize CA: %w", err)
	}

	return cm, nil
}

// GetCertificateForHost returns or generates a certificate for the specified host
func (cm *CertificateManager) GetCertificateForHost(host string) (*tls.Certificate, error) {
	cm.mutex.RLock()
	if cert, exists := cm.certificates[host]; exists {
		cm.mutex.RUnlock()
		return cert, nil
	}
	cm.mutex.RUnlock()

	// Generate new certificate
	cert, err := cm.generateCertificate(host)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate for %s: %w", host, err)
	}

	cm.mutex.Lock()
	cm.certificates[host] = cert
	cm.mutex.Unlock()

	return cert, nil
}

// initializeCA initializes the CA certificate and private key
func (cm *CertificateManager) initializeCA() error {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Vulnora Proxy"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Generate CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	cm.caCert = caCert
	cm.caKey = caKey

	cm.logger.Info("Initialized proxy CA certificate")
	return nil
}

// generateCertificate generates a new certificate for the specified host
func (cm *CertificateManager) generateCertificate(host string) (*tls.Certificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"Vulnora Proxy"},
			CommonName:   host,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Add SAN (Subject Alternative Name)
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, cm.caCert, &privateKey.PublicKey, cm.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate and key to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Create TLS certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	return &tlsCert, nil
}

// GetCACertificatePEM returns the CA certificate in PEM format
func (cm *CertificateManager) GetCACertificatePEM() ([]byte, error) {
	if cm.caCert == nil {
		return nil, fmt.Errorf("CA certificate not initialized")
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cm.caCert.Raw,
	}), nil
}

// ClearCache clears the certificate cache
func (cm *CertificateManager) ClearCache() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.certificates = make(map[string]*tls.Certificate)
	cm.logger.Info("Cleared certificate cache")
}
