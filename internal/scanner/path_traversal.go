package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"vulnora/internal/ai"
	"vulnora/internal/core"
)

// PathTraversalModule implements path traversal vulnerability detection
type PathTraversalModule struct {
	name        string
	description string
	enabled     bool
	config      *core.ScannerConfig
	aiEngine    *ai.Engine
	logger      *logrus.Logger
	payloads    []PathTraversalPayload
	mutex       sync.RWMutex
	progress    float64
}

// PathTraversalPayload represents a path traversal test payload
type PathTraversalPayload struct {
	Payload     string            `json:"payload"`
	OS          OSType            `json:"os"`
	Description string            `json:"description"`
	TargetFile  string            `json:"target_file"`
	Patterns    []string          `json:"patterns"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// NewPathTraversalModule creates a new path traversal detection module
func NewPathTraversalModule(config *core.ScannerConfig, aiEngine *ai.Engine, logger *logrus.Logger) *PathTraversalModule {
	module := &PathTraversalModule{
		name:        "path_traversal",
		description: "Detects path traversal (directory traversal) vulnerabilities",
		enabled:     true,
		config:      config,
		aiEngine:    aiEngine,
		logger:      logger,
	}

	module.initializePayloads()
	return module
}

// Name returns the module name
func (m *PathTraversalModule) Name() string {
	return m.name
}

// Description returns the module description
func (m *PathTraversalModule) Description() string {
	return m.description
}

// Enabled returns whether the module is enabled
func (m *PathTraversalModule) Enabled() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.enabled
}

// SetEnabled sets the module enabled state
func (m *PathTraversalModule) SetEnabled(enabled bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.enabled = enabled
}

// GetProgress returns the current scan progress
func (m *PathTraversalModule) GetProgress() float64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.progress
}

// Configure configures the module with provided settings
func (m *PathTraversalModule) Configure(config map[string]interface{}) error {
	// TODO: Implement module-specific configuration
	return nil
}

// Scan performs path traversal vulnerability detection
func (m *PathTraversalModule) Scan(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
	m.mutex.Lock()
	m.progress = 0.0
	m.mutex.Unlock()

	defer func() {
		m.mutex.Lock()
		m.progress = 100.0
		m.mutex.Unlock()
	}()

	var vulnerabilities []*core.Vulnerability

	m.logger.Debugf("Starting path traversal scan for: %s", target.URL)

	// Test URL parameters
	if urlVulns, err := m.testURLParameters(ctx, target); err == nil {
		vulnerabilities = append(vulnerabilities, urlVulns...)
	}

	// Update progress
	m.mutex.Lock()
	m.progress = 50.0
	m.mutex.Unlock()

	// Test POST parameters
	if postVulns, err := m.testPOSTParameters(ctx, target); err == nil {
		vulnerabilities = append(vulnerabilities, postVulns...)
	}

	m.logger.Debugf("Path traversal scan completed for: %s, found %d vulnerabilities",
		target.URL, len(vulnerabilities))

	return vulnerabilities, nil
}

// testURLParameters tests URL parameters for path traversal
func (m *PathTraversalModule) testURLParameters(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
	var vulnerabilities []*core.Vulnerability

	for param, value := range target.Parameters {
		// Only test parameters that might contain file paths
		if !m.isFileParameter(param, value) {
			continue
		}

		for _, payload := range m.payloads {
			select {
			case <-ctx.Done():
				return vulnerabilities, ctx.Err()
			default:
			}

			vuln, err := m.testParameter(ctx, target, param, value, payload, "url_parameter")
			if err != nil {
				m.logger.Debugf("Error testing URL parameter %s: %v", param, err)
				continue
			}

			if vuln != nil {
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities, nil
}

// testPOSTParameters tests POST parameters for path traversal
func (m *PathTraversalModule) testPOSTParameters(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
	var vulnerabilities []*core.Vulnerability

	// Parse POST body to extract parameters
	postParams := m.extractPOSTParameters(target.Body)

	for param, value := range postParams {
		// Only test parameters that might contain file paths
		if !m.isFileParameter(param, value) {
			continue
		}

		for _, payload := range m.payloads {
			select {
			case <-ctx.Done():
				return vulnerabilities, ctx.Err()
			default:
			}

			vuln, err := m.testParameter(ctx, target, param, value, payload, "post_parameter")
			if err != nil {
				m.logger.Debugf("Error testing POST parameter %s: %v", param, err)
				continue
			}

			if vuln != nil {
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities, nil
}

// testParameter tests a specific parameter with a path traversal payload
func (m *PathTraversalModule) testParameter(ctx context.Context, target *ScanTarget, param, originalValue string, payload PathTraversalPayload, location string) (*core.Vulnerability, error) {
	// Create test request
	testRequest := m.createTestRequest(target, param, originalValue, payload, location)

	// Send request
	response, err := m.sendRequest(ctx, testRequest)
	if err != nil {
		return nil, err
	}

	// Analyze response
	isVulnerable, evidence := m.analyzeResponse(response, payload)

	if !isVulnerable {
		return nil, nil
	}

	// Create vulnerability object
	vuln := &core.Vulnerability{
		ID:          generateVulnID(),
		Type:        core.VulnLFI, // Local File Inclusion/Path Traversal
		Severity:    core.SeverityHigh,
		Title:       fmt.Sprintf("Path Traversal in %s parameter '%s'", location, param),
		Description: fmt.Sprintf("Path traversal vulnerability detected in %s parameter '%s'. An attacker can read arbitrary files from the server.", location, param),
		Evidence:    fmt.Sprintf("Path traversal detected with payload: %s", payload.Payload),
		Parameter:   param,
		Payload:     payload.Payload,
		Location:    core.VulnerabilityLocation(location),
		Confidence:  m.calculateConfidence(payload, evidence),
		Remediation: "Validate and sanitize file paths. Use a whitelist of allowed files/directories. Avoid user input in file system operations.",
		References: []string{
			"https://owasp.org/www-community/attacks/Path_Traversal",
			"https://cwe.mitre.org/data/definitions/22.html",
		},
		CVSSScore:    7.5,
		CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		DiscoveredAt: time.Now(),
		UpdatedAt:    time.Now(),
		Metadata: map[string]interface{}{
			"target_os":        payload.OS,
			"target_file":      payload.TargetFile,
			"evidence_details": evidence,
		},
	}

	// Enhance with AI if available
	if m.aiEngine != nil {
		m.enhanceWithAI(ctx, vuln)
	}

	return vuln, nil
}

// createTestRequest creates a test request with the path traversal payload
func (m *PathTraversalModule) createTestRequest(target *ScanTarget, param, originalValue string, payload PathTraversalPayload, location string) *http.Request {
	// TODO: Implement request creation logic
	// This should modify the appropriate parameter based on location
	return nil
}

// sendRequest sends a test request and returns the response
func (m *PathTraversalModule) sendRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	return client.Do(req.WithContext(ctx))
}

// analyzeResponse analyzes the response for path traversal indicators
func (m *PathTraversalModule) analyzeResponse(response *http.Response, payload PathTraversalPayload) (bool, map[string]interface{}) {
	evidence := make(map[string]interface{})

	// TODO: Read response body safely
	responseBody := ""

	// Check for file content patterns
	for _, pattern := range payload.Patterns {
		if strings.Contains(responseBody, pattern) {
			evidence["pattern_matched"] = pattern
			evidence["file_content_detected"] = true
			return true, evidence
		}
	}

	// Check for specific file signatures
	if m.containsFileSignature(responseBody, payload.TargetFile) {
		evidence["file_signature"] = payload.TargetFile
		evidence["file_read"] = true
		return true, evidence
	}

	// Check response size - files are usually larger than error responses
	if response.ContentLength > 1000 {
		evidence["large_response"] = response.ContentLength
	}

	// Check content type
	contentType := response.Header.Get("Content-Type")
	if contentType != "" && !strings.Contains(contentType, "text/html") {
		evidence["non_html_content"] = contentType
	}

	return false, evidence
}

// containsFileSignature checks if response contains file-specific signatures
func (m *PathTraversalModule) containsFileSignature(responseBody, targetFile string) bool {
	signatures := map[string][]string{
		"/etc/passwd": {
			"root:x:0:0:",
			"bin:x:1:1:",
			"daemon:x:2:2:",
		},
		"/etc/shadow": {
			"root:$",
			"bin:*:",
			"daemon:*:",
		},
		"/proc/version": {
			"Linux version",
			"gcc version",
		},
		"boot.ini": {
			"[boot loader]",
			"[operating systems]",
		},
		"win.ini": {
			"[fonts]",
			"[extensions]",
		},
	}

	if sigs, exists := signatures[targetFile]; exists {
		for _, sig := range sigs {
			if strings.Contains(responseBody, sig) {
				return true
			}
		}
	}

	return false
}

// calculateConfidence calculates confidence level for the vulnerability
func (m *PathTraversalModule) calculateConfidence(payload PathTraversalPayload, evidence map[string]interface{}) core.ConfidenceLevel {
	confidence := 0.3 // Base confidence

	// Increase confidence based on evidence
	if _, exists := evidence["pattern_matched"]; exists {
		confidence += 0.5
	}

	if _, exists := evidence["file_signature"]; exists {
		confidence += 0.6
	}

	if _, exists := evidence["file_content_detected"]; exists {
		confidence += 0.4
	}

	if _, exists := evidence["file_read"]; exists {
		confidence += 0.5
	}

	// Convert to ConfidenceLevel
	if confidence >= 0.8 {
		return core.ConfidenceCertain
	} else if confidence >= 0.6 {
		return core.ConfidenceHigh
	} else if confidence >= 0.4 {
		return core.ConfidenceMedium
	} else {
		return core.ConfidenceLow
	}
}

// enhanceWithAI enhances the vulnerability with AI analysis
func (m *PathTraversalModule) enhanceWithAI(ctx context.Context, vuln *core.Vulnerability) {
	if m.aiEngine != nil {
		// Create context for AI analysis
		context := map[string]interface{}{
			"parameter": vuln.Parameter,
			"payload":   vuln.Payload,
			"location":  vuln.Location,
		}

		// Get AI suggestions for exploitation
		exploits, err := m.aiEngine.SuggestExploits(vuln, context)
		if err == nil && len(exploits) > 0 {
			// Add exploit suggestions to metadata
			if vuln.Metadata == nil {
				vuln.Metadata = make(map[string]interface{})
			}
			vuln.Metadata["ai_exploits"] = exploits
			vuln.AIGenerated = true
		}
	}
}

// Helper methods

// isFileParameter checks if a parameter likely contains file paths
func (m *PathTraversalModule) isFileParameter(param, value string) bool {
	param = strings.ToLower(param)
	value = strings.ToLower(value)

	// Check parameter names
	fileParams := []string{
		"file", "filename", "filepath", "path", "dir", "directory",
		"page", "template", "include", "document", "doc", "load",
		"read", "open", "get", "fetch", "download", "upload",
	}

	for _, fp := range fileParams {
		if strings.Contains(param, fp) {
			return true
		}
	}

	// Check value patterns
	if strings.Contains(value, "/") || strings.Contains(value, "\\") {
		return true
	}

	if strings.Contains(value, ".") && (strings.Contains(value, "txt") ||
		strings.Contains(value, "ini") || strings.Contains(value, "cfg") ||
		strings.Contains(value, "conf") || strings.Contains(value, "log")) {
		return true
	}

	return false
}

// extractPOSTParameters extracts parameters from POST body
func (m *PathTraversalModule) extractPOSTParameters(body []byte) map[string]string {
	params := make(map[string]string)

	// TODO: Implement POST parameter extraction
	// Handle form-data, JSON, XML, etc.

	return params
}

// initializePayloads initializes path traversal test payloads
func (m *PathTraversalModule) initializePayloads() {
	m.payloads = []PathTraversalPayload{
		// Basic Unix/Linux payloads
		{
			Payload:     "../../../etc/passwd",
			OS:          OSTypeUnix,
			Description: "Basic Unix passwd file access",
			TargetFile:  "/etc/passwd",
			Patterns:    []string{"root:x:0:0:", "bin:x:1:1:"},
		},
		{
			Payload:     "../../../../etc/passwd",
			OS:          OSTypeUnix,
			Description: "Extended Unix passwd file access",
			TargetFile:  "/etc/passwd",
			Patterns:    []string{"root:x:0:0:", "bin:x:1:1:"},
		},
		{
			Payload:     "../../../../../etc/shadow",
			OS:          OSTypeUnix,
			Description: "Unix shadow file access",
			TargetFile:  "/etc/shadow",
			Patterns:    []string{"root:$", "bin:*:"},
		},
		{
			Payload:     "../../proc/version",
			OS:          OSTypeUnix,
			Description: "Linux kernel version",
			TargetFile:  "/proc/version",
			Patterns:    []string{"Linux version", "gcc version"},
		},

		// Basic Windows payloads
		{
			Payload:     "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
			OS:          OSTypeWindows,
			Description: "Windows hosts file",
			TargetFile:  "hosts",
			Patterns:    []string{"localhost", "127.0.0.1"},
		},
		{
			Payload:     "..\\..\\boot.ini",
			OS:          OSTypeWindows,
			Description: "Windows boot configuration",
			TargetFile:  "boot.ini",
			Patterns:    []string{"[boot loader]", "[operating systems]"},
		},
		{
			Payload:     "..\\..\\..\\windows\\win.ini",
			OS:          OSTypeWindows,
			Description: "Windows configuration file",
			TargetFile:  "win.ini",
			Patterns:    []string{"[fonts]", "[extensions]"},
		},

		// URL encoded payloads
		{
			Payload:     "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			OS:          OSTypeUnix,
			Description: "URL encoded passwd access",
			TargetFile:  "/etc/passwd",
			Patterns:    []string{"root:x:0:0:", "bin:x:1:1:"},
		},
		{
			Payload:     "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
			OS:          OSTypeWindows,
			Description: "URL encoded Windows hosts",
			TargetFile:  "hosts",
			Patterns:    []string{"localhost", "127.0.0.1"},
		},

		// Double encoded payloads
		{
			Payload:     "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
			OS:          OSTypeUnix,
			Description: "Double URL encoded passwd access",
			TargetFile:  "/etc/passwd",
			Patterns:    []string{"root:x:0:0:", "bin:x:1:1:"},
		},

		// Unicode encoded payloads
		{
			Payload:     "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
			OS:          OSTypeUnix,
			Description: "Unicode encoded passwd access",
			TargetFile:  "/etc/passwd",
			Patterns:    []string{"root:x:0:0:", "bin:x:1:1:"},
		},

		// Null byte injection (for older systems)
		{
			Payload:     "../../../etc/passwd%00.jpg",
			OS:          OSTypeUnix,
			Description: "Null byte injection passwd access",
			TargetFile:  "/etc/passwd",
			Patterns:    []string{"root:x:0:0:", "bin:x:1:1:"},
		},

		// Application-specific paths
		{
			Payload:     "../../../var/log/apache2/access.log",
			OS:          OSTypeUnix,
			Description: "Apache access log",
			TargetFile:  "access.log",
			Patterns:    []string{"GET /", "POST /", "User-Agent:"},
		},
		{
			Payload:     "../../../var/log/nginx/access.log",
			OS:          OSTypeUnix,
			Description: "Nginx access log",
			TargetFile:  "access.log",
			Patterns:    []string{"GET /", "POST /", "HTTP/"},
		},
	}
}
