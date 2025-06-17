package scanner

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"vulnora/internal/ai"
	"vulnora/internal/core"
)

// XSSModule implements Cross-Site Scripting vulnerability detection
type XSSModule struct {
	name        string
	description string
	enabled     bool
	config      *core.ScannerConfig
	aiEngine    *ai.Engine
	logger      *logrus.Logger
	payloads    []XSSPayload
	mutex       sync.RWMutex
	progress    float64
}

// XSSPayload represents an XSS test payload
type XSSPayload struct {
	Payload     string            `json:"payload"`
	Type        XSSType           `json:"type"`
	Context     XSSContext        `json:"context"`
	Description string            `json:"description"`
	Patterns    []string          `json:"patterns"`
	UniqueID    string            `json:"unique_id"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// XSSType represents the type of XSS
type XSSType int

const (
	XSSTypeReflected XSSType = iota
	XSSTypeStored
	XSSTypeDOM
	XSSTypeBlind
)

// XSSContext represents where the XSS occurs
type XSSContext int

const (
	XSSContextHTML XSSContext = iota
	XSSContextAttribute
	XSSContextJavaScript
	XSSContextCSS
	XSSContextURL
	XSSContextComment
)

// NewXSSModule creates a new XSS detection module
func NewXSSModule(config *core.ScannerConfig, aiEngine *ai.Engine, logger *logrus.Logger) *XSSModule {
	module := &XSSModule{
		name:        "xss",
		description: "Detects Cross-Site Scripting (XSS) vulnerabilities",
		enabled:     true,
		config:      config,
		aiEngine:    aiEngine,
		logger:      logger,
	}

	module.initializePayloads()
	return module
}

// Name returns the module name
func (m *XSSModule) Name() string {
	return m.name
}

// Description returns the module description
func (m *XSSModule) Description() string {
	return m.description
}

// Enabled returns whether the module is enabled
func (m *XSSModule) Enabled() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.enabled
}

// SetEnabled sets the module enabled state
func (m *XSSModule) SetEnabled(enabled bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.enabled = enabled
}

// GetProgress returns the current scan progress
func (m *XSSModule) GetProgress() float64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.progress
}

// Configure configures the module with provided settings
func (m *XSSModule) Configure(config map[string]interface{}) error {
	// TODO: Implement module-specific configuration
	return nil
}

// Scan performs XSS vulnerability detection
func (m *XSSModule) Scan(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
	m.mutex.Lock()
	m.progress = 0.0
	m.mutex.Unlock()

	defer func() {
		m.mutex.Lock()
		m.progress = 100.0
		m.mutex.Unlock()
	}()

	var vulnerabilities []*core.Vulnerability

	m.logger.Debugf("Starting XSS scan for: %s", target.URL)

	// Test URL parameters
	if urlVulns, err := m.testURLParameters(ctx, target); err == nil {
		vulnerabilities = append(vulnerabilities, urlVulns...)
	}

	// Update progress
	m.mutex.Lock()
	m.progress = 25.0
	m.mutex.Unlock()

	// Test POST parameters
	if postVulns, err := m.testPOSTParameters(ctx, target); err == nil {
		vulnerabilities = append(vulnerabilities, postVulns...)
	}

	// Update progress
	m.mutex.Lock()
	m.progress = 50.0
	m.mutex.Unlock()

	// Test headers
	if headerVulns, err := m.testHeaders(ctx, target); err == nil {
		vulnerabilities = append(vulnerabilities, headerVulns...)
	}

	// Update progress
	m.mutex.Lock()
	m.progress = 75.0
	m.mutex.Unlock()

	// Test for DOM-based XSS
	if domVulns, err := m.testDOMXSS(ctx, target); err == nil {
		vulnerabilities = append(vulnerabilities, domVulns...)
	}

	m.logger.Debugf("XSS scan completed for: %s, found %d vulnerabilities",
		target.URL, len(vulnerabilities))

	return vulnerabilities, nil
}

// testURLParameters tests URL parameters for XSS
func (m *XSSModule) testURLParameters(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
	var vulnerabilities []*core.Vulnerability

	for param, value := range target.Parameters {
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

// testPOSTParameters tests POST parameters for XSS
func (m *XSSModule) testPOSTParameters(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
	var vulnerabilities []*core.Vulnerability

	// Parse POST body to extract parameters
	postParams := m.extractPOSTParameters(target.Body)

	for param, value := range postParams {
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

// testHeaders tests HTTP headers for XSS
func (m *XSSModule) testHeaders(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
	var vulnerabilities []*core.Vulnerability

	// Test common injectable headers
	injectableHeaders := []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"}

	for _, header := range injectableHeaders {
		if value, exists := target.Headers[header]; exists {
			for _, payload := range m.payloads {
				select {
				case <-ctx.Done():
					return vulnerabilities, ctx.Err()
				default:
				}

				vuln, err := m.testParameter(ctx, target, header, value, payload, "header")
				if err != nil {
					m.logger.Debugf("Error testing header %s: %v", header, err)
					continue
				}

				if vuln != nil {
					vulnerabilities = append(vulnerabilities, vuln)
				}
			}
		}
	}

	return vulnerabilities, nil
}

// testDOMXSS tests for DOM-based XSS vulnerabilities
func (m *XSSModule) testDOMXSS(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
	var vulnerabilities []*core.Vulnerability

	// TODO: Implement DOM XSS detection
	// This requires analyzing JavaScript code and DOM manipulation

	return vulnerabilities, nil
}

// testParameter tests a specific parameter with an XSS payload
func (m *XSSModule) testParameter(ctx context.Context, target *ScanTarget, param, originalValue string, payload XSSPayload, location string) (*core.Vulnerability, error) {
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
		Type:        core.VulnXSS,
		Severity:    m.calculateSeverity(payload.Type),
		Title:       fmt.Sprintf("%s XSS in %s parameter '%s'", m.getXSSTypeName(payload.Type), location, param),
		Description: fmt.Sprintf("%s Cross-Site Scripting vulnerability detected in %s parameter '%s'", m.getXSSTypeName(payload.Type), location, param),
		Evidence:    fmt.Sprintf("Payload: %s\nResponse indicators: %v", payload.Payload, evidence),
		Location:    core.VulnerabilityLocation(location),
		Parameter:   param,
		Payload:     payload.Payload,
		CVSSScore:   m.calculateCVSS(payload.Type),
		CVSSVector:  m.getCVSSVector(payload.Type),
		Confidence:  convertToConfidenceLevel(m.calculateConfidence(payload, evidence)),
		Remediation: m.getRemediation(payload.Type),
		References: []string{
			"https://owasp.org/www-community/attacks/xss/",
			"https://cwe.mitre.org/data/definitions/79.html",
		},
		DiscoveredAt: time.Now(),
		UpdatedAt:    time.Now(),
		AIGenerated:  false,
		Metadata: map[string]interface{}{
			"xss_type":      payload.Type,
			"xss_context":   payload.Context,
			"unique_id":     payload.UniqueID,
			"cwe":           "CWE-79",
			"owasp":         "A03:2021 – Injection",
			"evidence_data": evidence,
		},
	}

	// Enhance with AI if available
	if m.aiEngine != nil {
		m.enhanceWithAI(ctx, vuln)
	}

	return vuln, nil
}

// createTestRequest creates a test request with the XSS payload
func (m *XSSModule) createTestRequest(target *ScanTarget, param, originalValue string, payload XSSPayload, location string) *http.Request {
	// TODO: Implement request creation logic
	// This should modify the appropriate part of the request based on location
	return nil
}

// sendRequest sends a test request and returns the response
func (m *XSSModule) sendRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	return client.Do(req.WithContext(ctx))
}

// analyzeResponse analyzes the response for XSS indicators
func (m *XSSModule) analyzeResponse(response *http.Response, payload XSSPayload) (bool, map[string]interface{}) {
	evidence := make(map[string]interface{})

	// TODO: Read response body safely
	// responseBody := readResponseBody(response)
	responseBody := ""

	// Check if payload is reflected in response
	if strings.Contains(responseBody, payload.UniqueID) {
		evidence["reflected"] = true
		evidence["reflection_count"] = strings.Count(responseBody, payload.UniqueID)

		// Check for specific XSS patterns
		for _, pattern := range payload.Patterns {
			if matched, _ := regexp.MatchString(pattern, responseBody); matched {
				evidence["pattern_matched"] = pattern
				evidence["vulnerable"] = true
				return true, evidence
			}
		}

		// Check for script execution context
		if m.isInExecutableContext(responseBody, payload.UniqueID) {
			evidence["executable_context"] = true
			evidence["vulnerable"] = true
			return true, evidence
		}
	}

	// Check Content-Type header for potential issues
	contentType := response.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "text/html") {
		evidence["non_html_content"] = contentType
	}

	// Check for X-XSS-Protection header
	xssProtection := response.Header.Get("X-XSS-Protection")
	if xssProtection != "" {
		evidence["xss_protection_header"] = xssProtection
	}

	// Check for Content-Security-Policy header
	csp := response.Header.Get("Content-Security-Policy")
	if csp != "" {
		evidence["csp_header"] = csp
	}

	return false, evidence
}

// isInExecutableContext checks if the payload is in an executable JavaScript context
func (m *XSSModule) isInExecutableContext(responseBody, uniqueID string) bool {
	// Find the position of the unique ID in the response
	pos := strings.Index(responseBody, uniqueID)
	if pos == -1 {
		return false
	}

	// Check surrounding context
	start := pos - 100
	if start < 0 {
		start = 0
	}
	end := pos + len(uniqueID) + 100
	if end > len(responseBody) {
		end = len(responseBody)
	}

	context := responseBody[start:end]

	// Check for script tags
	if strings.Contains(context, "<script") || strings.Contains(context, "</script>") {
		return true
	}

	// Check for event handlers
	eventHandlers := []string{"onclick", "onload", "onmouseover", "onerror", "onsubmit"}
	for _, handler := range eventHandlers {
		if strings.Contains(strings.ToLower(context), handler) {
			return true
		}
	}

	// Check for javascript: URLs
	if strings.Contains(strings.ToLower(context), "javascript:") {
		return true
	}

	return false
}

// calculateSeverity calculates the severity based on XSS type
func (m *XSSModule) calculateSeverity(xssType XSSType) core.Severity {
	switch xssType {
	case XSSTypeStored:
		return core.SeverityHigh
	case XSSTypeReflected:
		return core.SeverityMedium
	case XSSTypeDOM:
		return core.SeverityMedium
	case XSSTypeBlind:
		return core.SeverityLow
	default:
		return core.SeverityMedium
	}
}

// calculateCVSS calculates CVSS score based on XSS type
func (m *XSSModule) calculateCVSS(xssType XSSType) float64 {
	switch xssType {
	case XSSTypeStored:
		return 8.8
	case XSSTypeReflected:
		return 6.1
	case XSSTypeDOM:
		return 6.1
	case XSSTypeBlind:
		return 4.3
	default:
		return 6.1
	}
}

// calculateConfidence calculates confidence level for the vulnerability
func (m *XSSModule) calculateConfidence(payload XSSPayload, evidence map[string]interface{}) float64 {
	confidence := 0.3 // Base confidence

	if _, exists := evidence["reflected"]; exists {
		confidence += 0.3
	}

	if _, exists := evidence["pattern_matched"]; exists {
		confidence += 0.3
	}

	if _, exists := evidence["executable_context"]; exists {
		confidence += 0.4
	}

	// Cap confidence at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// getCVSSVector returns the CVSS vector for XSS type
func (m *XSSModule) getCVSSVector(xssType XSSType) string {
	switch xssType {
	case XSSTypeReflected:
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
	case XSSTypeStored:
		return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"
	case XSSTypeDOM:
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
	default:
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
	}
}

// getXSSTypeName returns human-readable XSS type name
func (m *XSSModule) getXSSTypeName(xssType XSSType) string {
	switch xssType {
	case XSSTypeReflected:
		return "Reflected"
	case XSSTypeStored:
		return "Stored"
	case XSSTypeDOM:
		return "DOM-based"
	case XSSTypeBlind:
		return "Blind"
	default:
		return "Unknown"
	}
}

// getRemediation returns remediation advice based on XSS type
func (m *XSSModule) getRemediation(xssType XSSType) string {
	switch xssType {
	case XSSTypeReflected:
		return "Validate and encode all user input before reflecting it in HTML output. Use Content Security Policy (CSP) headers."
	case XSSTypeStored:
		return "Validate and encode all user input before storing and displaying it. Implement proper output encoding based on context."
	case XSSTypeDOM:
		return "Avoid using dangerous JavaScript functions like eval(), innerHTML, and document.write() with user input. Use safe DOM manipulation methods."
	case XSSTypeBlind:
		return "Implement proper input validation and output encoding even for data that is not immediately displayed to users."
	default:
		return "Implement comprehensive input validation and output encoding for all user-controlled data."
	}
}

// enhanceWithAI enhances the vulnerability with AI analysis
func (m *XSSModule) enhanceWithAI(ctx context.Context, vuln *core.Vulnerability) {
	if m.aiEngine != nil {
		// Get AI suggestions for exploitation
		exploits, err := m.aiEngine.SuggestExploits(vuln, make(map[string]interface{}))
		if err == nil && len(exploits) > 0 {
			if vuln.Metadata == nil {
				vuln.Metadata = make(map[string]interface{})
			}
			vuln.Metadata["ai_exploits"] = exploits
			vuln.AIGenerated = true
		}
	}
}

// extractPOSTParameters extracts parameters from POST body
func (m *XSSModule) extractPOSTParameters(body []byte) map[string]string {
	params := make(map[string]string)

	// TODO: Implement POST parameter extraction
	// Handle form-data, JSON, XML, etc.

	return params
}

// initializePayloads initializes XSS test payloads
func (m *XSSModule) initializePayloads() {
	m.payloads = []XSSPayload{
		// Basic script tags
		{
			Payload:     "<script>alert('XSS')</script>",
			Type:        XSSTypeReflected,
			Context:     XSSContextHTML,
			Description: "Basic script tag injection",
			Patterns:    []string{`<script>alert\('XSS'\)</script>`},
			UniqueID:    "XSS",
		},
		{
			Payload:     "<script>alert(document.domain)</script>",
			Type:        XSSTypeReflected,
			Context:     XSSContextHTML,
			Description: "Script tag with document.domain",
			Patterns:    []string{`<script>alert\(document\.domain\)</script>`},
			UniqueID:    "document.domain",
		},

		// Event handlers
		{
			Payload:     "<img src=x onerror=alert('XSS')>",
			Type:        XSSTypeReflected,
			Context:     XSSContextHTML,
			Description: "Image tag with onerror event",
			Patterns:    []string{`<img.*onerror=alert\('XSS'\)`},
			UniqueID:    "onerror",
		},
		{
			Payload:     "<body onload=alert('XSS')>",
			Type:        XSSTypeReflected,
			Context:     XSSContextHTML,
			Description: "Body tag with onload event",
			Patterns:    []string{`<body.*onload=alert\('XSS'\)`},
			UniqueID:    "onload",
		},

		// JavaScript URLs
		{
			Payload:     "javascript:alert('XSS')",
			Type:        XSSTypeReflected,
			Context:     XSSContextURL,
			Description: "JavaScript URL scheme",
			Patterns:    []string{`javascript:alert\('XSS'\)`},
			UniqueID:    "javascript:",
		},

		// Attribute context
		{
			Payload:     "' onmouseover='alert(\"XSS\")'",
			Type:        XSSTypeReflected,
			Context:     XSSContextAttribute,
			Description: "Attribute escape with event handler",
			Patterns:    []string{`onmouseover='alert\("XSS"\)'`},
			UniqueID:    "onmouseover",
		},

		// Filter bypasses
		{
			Payload:     "<svg onload=alert('XSS')>",
			Type:        XSSTypeReflected,
			Context:     XSSContextHTML,
			Description: "SVG tag with onload event",
			Patterns:    []string{`<svg.*onload=alert\('XSS'\)`},
			UniqueID:    "svgonload",
		},
		{
			Payload:     "<iframe src=\"javascript:alert('XSS')\">",
			Type:        XSSTypeReflected,
			Context:     XSSContextHTML,
			Description: "Iframe with javascript URL",
			Patterns:    []string{`<iframe.*javascript:alert\('XSS'\)`},
			UniqueID:    "iframejs",
		},

		// Polyglot payloads
		{
			Payload:     "'\"><script>alert('XSS')</script>",
			Type:        XSSTypeReflected,
			Context:     XSSContextHTML,
			Description: "Polyglot payload for multiple contexts",
			Patterns:    []string{`'\"><script>alert\('XSS'\)</script>`},
			UniqueID:    "polyglot",
		},

		// Template injection that could lead to XSS
		{
			Payload:     "{{alert('XSS')}}",
			Type:        XSSTypeReflected,
			Context:     XSSContextHTML,
			Description: "Template injection attempt",
			Patterns:    []string{`\{\{alert\('XSS'\)\}\}`},
			UniqueID:    "template",
		},

		// DOM XSS payloads
		{
			Payload:     "#<script>alert('DOM-XSS')</script>",
			Type:        XSSTypeDOM,
			Context:     XSSContextHTML,
			Description: "DOM XSS via URL fragment",
			Patterns:    []string{`<script>alert\('DOM-XSS'\)</script>`},
			UniqueID:    "DOM-XSS",
		},
	}
}
