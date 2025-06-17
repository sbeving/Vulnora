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

// CSRFModule implements Cross-Site Request Forgery vulnerability detection
type CSRFModule struct {
	name        string
	description string
	enabled     bool
	config      *core.ScannerConfig
	aiEngine    *ai.Engine
	logger      *logrus.Logger
	mutex       sync.RWMutex
	progress    float64
}

// CSRFTest represents a CSRF test case
type CSRFTest struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        []byte            `json:"body"`
	Description string            `json:"description"`
	TestType    CSRFTestType      `json:"test_type"`
}

// CSRFTestType represents the type of CSRF test
type CSRFTestType int

const (
	CSRFTestTokenMissing CSRFTestType = iota
	CSRFTestTokenInvalid
	CSRFTestTokenReplay
	CSRFTestReferrerMissing
	CSRFTestOriginMissing
	CSRFTestSameOrigin
)

// NewCSRFModule creates a new CSRF detection module
func NewCSRFModule(config *core.ScannerConfig, aiEngine *ai.Engine, logger *logrus.Logger) *CSRFModule {
	module := &CSRFModule{
		name:        "csrf",
		description: "Detects Cross-Site Request Forgery (CSRF) vulnerabilities",
		enabled:     true,
		config:      config,
		aiEngine:    aiEngine,
		logger:      logger,
	}

	return module
}

// Name returns the module name
func (m *CSRFModule) Name() string {
	return m.name
}

// Description returns the module description
func (m *CSRFModule) Description() string {
	return m.description
}

// Enabled returns whether the module is enabled
func (m *CSRFModule) Enabled() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.enabled
}

// SetEnabled sets the module enabled state
func (m *CSRFModule) SetEnabled(enabled bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.enabled = enabled
}

// GetProgress returns the current scan progress
func (m *CSRFModule) GetProgress() float64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.progress
}

// Configure configures the module with provided settings
func (m *CSRFModule) Configure(config map[string]interface{}) error {
	// TODO: Implement module-specific configuration
	return nil
}

// Scan performs CSRF vulnerability detection
func (m *CSRFModule) Scan(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
	m.mutex.Lock()
	m.progress = 0.0
	m.mutex.Unlock()

	defer func() {
		m.mutex.Lock()
		m.progress = 100.0
		m.mutex.Unlock()
	}()

	var vulnerabilities []*core.Vulnerability

	m.logger.Debugf("Starting CSRF scan for: %s", target.URL)

	// Only test state-changing requests (POST, PUT, DELETE, PATCH)
	if !m.isStateChangingRequest(target.Method) {
		m.logger.Debugf("Skipping CSRF test for non-state-changing method: %s", target.Method)
		return vulnerabilities, nil
	}

	// Test for missing CSRF tokens
	if vuln, err := m.testMissingCSRFToken(ctx, target); err == nil && vuln != nil {
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Update progress
	m.mutex.Lock()
	m.progress = 25.0
	m.mutex.Unlock()

	// Test for invalid CSRF tokens
	if vuln, err := m.testInvalidCSRFToken(ctx, target); err == nil && vuln != nil {
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Update progress
	m.mutex.Lock()
	m.progress = 50.0
	m.mutex.Unlock()

	// Test for missing Referer header
	if vuln, err := m.testMissingReferer(ctx, target); err == nil && vuln != nil {
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Update progress
	m.mutex.Lock()
	m.progress = 75.0
	m.mutex.Unlock()

	// Test for missing Origin header
	if vuln, err := m.testMissingOrigin(ctx, target); err == nil && vuln != nil {
		vulnerabilities = append(vulnerabilities, vuln)
	}

	m.logger.Debugf("CSRF scan completed for: %s, found %d vulnerabilities",
		target.URL, len(vulnerabilities))

	return vulnerabilities, nil
}

// testMissingCSRFToken tests for missing CSRF token protection
func (m *CSRFModule) testMissingCSRFToken(ctx context.Context, target *ScanTarget) (*core.Vulnerability, error) {
	// Create test request without CSRF token
	testRequest := m.createTestRequest(target, CSRFTestTokenMissing)

	// Send original request
	originalResponse, err := m.sendOriginalRequest(ctx, target)
	if err != nil {
		return nil, err
	}

	// Send test request
	testResponse, err := m.sendRequest(ctx, testRequest)
	if err != nil {
		return nil, err
	}

	// Analyze responses
	isVulnerable, evidence := m.analyzeCSRFResponse(originalResponse, testResponse, CSRFTestTokenMissing)

	if !isVulnerable {
		return nil, nil
	}

	return m.createVulnerability(target, CSRFTestTokenMissing, evidence), nil
}

// testInvalidCSRFToken tests for invalid CSRF token handling
func (m *CSRFModule) testInvalidCSRFToken(ctx context.Context, target *ScanTarget) (*core.Vulnerability, error) {
	// Create test request with invalid CSRF token
	testRequest := m.createTestRequest(target, CSRFTestTokenInvalid)

	// Send original request
	originalResponse, err := m.sendOriginalRequest(ctx, target)
	if err != nil {
		return nil, err
	}

	// Send test request
	testResponse, err := m.sendRequest(ctx, testRequest)
	if err != nil {
		return nil, err
	}

	// Analyze responses
	isVulnerable, evidence := m.analyzeCSRFResponse(originalResponse, testResponse, CSRFTestTokenInvalid)

	if !isVulnerable {
		return nil, nil
	}

	return m.createVulnerability(target, CSRFTestTokenInvalid, evidence), nil
}

// testMissingReferer tests for missing Referer header protection
func (m *CSRFModule) testMissingReferer(ctx context.Context, target *ScanTarget) (*core.Vulnerability, error) {
	// Create test request without Referer header
	testRequest := m.createTestRequest(target, CSRFTestReferrerMissing)

	// Send original request
	originalResponse, err := m.sendOriginalRequest(ctx, target)
	if err != nil {
		return nil, err
	}

	// Send test request
	testResponse, err := m.sendRequest(ctx, testRequest)
	if err != nil {
		return nil, err
	}

	// Analyze responses
	isVulnerable, evidence := m.analyzeCSRFResponse(originalResponse, testResponse, CSRFTestReferrerMissing)

	if !isVulnerable {
		return nil, nil
	}

	return m.createVulnerability(target, CSRFTestReferrerMissing, evidence), nil
}

// testMissingOrigin tests for missing Origin header protection
func (m *CSRFModule) testMissingOrigin(ctx context.Context, target *ScanTarget) (*core.Vulnerability, error) {
	// Create test request without Origin header
	testRequest := m.createTestRequest(target, CSRFTestOriginMissing)

	// Send original request
	originalResponse, err := m.sendOriginalRequest(ctx, target)
	if err != nil {
		return nil, err
	}

	// Send test request
	testResponse, err := m.sendRequest(ctx, testRequest)
	if err != nil {
		return nil, err
	}

	// Analyze responses
	isVulnerable, evidence := m.analyzeCSRFResponse(originalResponse, testResponse, CSRFTestOriginMissing)

	if !isVulnerable {
		return nil, nil
	}

	return m.createVulnerability(target, CSRFTestOriginMissing, evidence), nil
}

// createTestRequest creates a test request based on the test type
func (m *CSRFModule) createTestRequest(target *ScanTarget, testType CSRFTestType) *http.Request {
	// TODO: Implement request creation logic based on test type
	// This should modify the request according to the specific CSRF test
	return nil
}

// sendOriginalRequest sends the original request
func (m *CSRFModule) sendOriginalRequest(ctx context.Context, target *ScanTarget) (*http.Response, error) {
	// TODO: Create and send the original request
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Create original request from target
	req, err := http.NewRequest(target.Method, target.URL, nil)
	if err != nil {
		return nil, err
	}

	// Add headers
	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	return client.Do(req.WithContext(ctx))
}

// sendRequest sends a test request and returns the response
func (m *CSRFModule) sendRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	return client.Do(req.WithContext(ctx))
}

// analyzeCSRFResponse analyzes responses for CSRF vulnerabilities
func (m *CSRFModule) analyzeCSRFResponse(originalResp, testResp *http.Response, testType CSRFTestType) (bool, map[string]interface{}) {
	evidence := make(map[string]interface{})

	// Check status codes
	evidence["original_status"] = originalResp.StatusCode
	evidence["test_status"] = testResp.StatusCode

	// If both requests succeed, likely vulnerable to CSRF
	if originalResp.StatusCode >= 200 && originalResp.StatusCode < 300 &&
		testResp.StatusCode >= 200 && testResp.StatusCode < 300 {

		evidence["both_requests_successful"] = true

		// Additional checks based on test type
		switch testType {
		case CSRFTestTokenMissing:
			evidence["csrf_token_not_required"] = true
			return true, evidence

		case CSRFTestTokenInvalid:
			evidence["invalid_token_accepted"] = true
			return true, evidence

		case CSRFTestReferrerMissing:
			evidence["referer_not_required"] = true
			return true, evidence

		case CSRFTestOriginMissing:
			evidence["origin_not_required"] = true
			return true, evidence
		}
	}

	// Check for specific error messages that indicate CSRF protection
	if testResp.StatusCode == 403 || testResp.StatusCode == 400 {
		// TODO: Read and analyze response body for CSRF error messages
		evidence["potential_csrf_protection"] = true
		return false, evidence
	}

	// Check content length differences
	if originalResp.ContentLength != testResp.ContentLength {
		evidence["content_length_diff"] = map[string]int64{
			"original": originalResp.ContentLength,
			"test":     testResp.ContentLength,
		}
	}

	return false, evidence
}

// createVulnerability creates a CSRF vulnerability object
func (m *CSRFModule) createVulnerability(target *ScanTarget, testType CSRFTestType, evidence map[string]interface{}) *core.Vulnerability {
	vuln := &core.Vulnerability{
		ID:          generateVulnID(),
		Type:        core.VulnCSRF,
		Severity:    m.calculateSeverity(testType),
		Title:       fmt.Sprintf("Cross-Site Request Forgery (%s)", m.getTestTypeName(testType)),
		Description: fmt.Sprintf("CSRF vulnerability detected: %s. An attacker can perform unauthorized actions on behalf of authenticated users.", m.getTestTypeDescription(testType)),
		Evidence:    m.getTestTypeEvidence(testType, evidence),
		Parameter:   "",
		Payload:     m.getTestTypePayload(testType),
		Location:    core.LocationURL,
		Confidence:  m.calculateConfidence(testType, evidence),
		Remediation: m.getRemediation(testType),
		References: []string{
			"https://owasp.org/www-community/attacks/csrf",
			"https://cwe.mitre.org/data/definitions/352.html",
		},
		CVSSScore:    m.calculateCVSS(testType),
		CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
		DiscoveredAt: time.Now(),
		UpdatedAt:    time.Now(),
		Metadata: map[string]interface{}{
			"csrf_test_type":   testType,
			"target_method":    target.Method,
			"evidence_details": evidence,
		},
	}

	// Enhance with AI if available
	if m.aiEngine != nil {
		m.enhanceWithAI(context.Background(), vuln)
	}

	return vuln
}

// Helper methods

// isStateChangingRequest checks if the request method is state-changing
func (m *CSRFModule) isStateChangingRequest(method string) bool {
	stateChangingMethods := []string{"POST", "PUT", "DELETE", "PATCH"}
	method = strings.ToUpper(method)

	for _, scm := range stateChangingMethods {
		if method == scm {
			return true
		}
	}

	return false
}

// getTestTypeName returns a human-readable name for the test type
func (m *CSRFModule) getTestTypeName(testType CSRFTestType) string {
	switch testType {
	case CSRFTestTokenMissing:
		return "Missing CSRF Token"
	case CSRFTestTokenInvalid:
		return "Invalid CSRF Token"
	case CSRFTestTokenReplay:
		return "CSRF Token Replay"
	case CSRFTestReferrerMissing:
		return "Missing Referer Header"
	case CSRFTestOriginMissing:
		return "Missing Origin Header"
	case CSRFTestSameOrigin:
		return "Same Origin Policy Bypass"
	default:
		return "Unknown CSRF Test"
	}
}

// getTestTypeDescription returns a description for the test type
func (m *CSRFModule) getTestTypeDescription(testType CSRFTestType) string {
	switch testType {
	case CSRFTestTokenMissing:
		return "The application does not require CSRF tokens for state-changing requests"
	case CSRFTestTokenInvalid:
		return "The application accepts invalid CSRF tokens"
	case CSRFTestTokenReplay:
		return "The application allows CSRF token replay attacks"
	case CSRFTestReferrerMissing:
		return "The application does not validate the Referer header"
	case CSRFTestOriginMissing:
		return "The application does not validate the Origin header"
	case CSRFTestSameOrigin:
		return "The application's same-origin policy can be bypassed"
	default:
		return "Unknown CSRF vulnerability"
	}
}

// getTestTypeEvidence returns evidence text for the test type
func (m *CSRFModule) getTestTypeEvidence(testType CSRFTestType, evidence map[string]interface{}) string {
	switch testType {
	case CSRFTestTokenMissing:
		return "Request succeeded without CSRF token"
	case CSRFTestTokenInvalid:
		return "Request succeeded with invalid CSRF token"
	case CSRFTestReferrerMissing:
		return "Request succeeded without Referer header"
	case CSRFTestOriginMissing:
		return "Request succeeded without Origin header"
	default:
		return "CSRF protection bypass detected"
	}
}

// getTestTypePayload returns a payload example for the test type
func (m *CSRFModule) getTestTypePayload(testType CSRFTestType) string {
	switch testType {
	case CSRFTestTokenMissing:
		return "Request without CSRF token"
	case CSRFTestTokenInvalid:
		return "invalid_csrf_token_12345"
	case CSRFTestReferrerMissing:
		return "Request without Referer header"
	case CSRFTestOriginMissing:
		return "Request without Origin header"
	default:
		return "CSRF bypass attempt"
	}
}

// calculateSeverity calculates severity based on test type
func (m *CSRFModule) calculateSeverity(testType CSRFTestType) core.Severity {
	switch testType {
	case CSRFTestTokenMissing:
		return core.SeverityHigh
	case CSRFTestTokenInvalid:
		return core.SeverityHigh
	case CSRFTestReferrerMissing:
		return core.SeverityMedium
	case CSRFTestOriginMissing:
		return core.SeverityMedium
	default:
		return core.SeverityMedium
	}
}

// calculateCVSS calculates CVSS score based on test type
func (m *CSRFModule) calculateCVSS(testType CSRFTestType) float64 {
	switch testType {
	case CSRFTestTokenMissing:
		return 8.1
	case CSRFTestTokenInvalid:
		return 8.1
	case CSRFTestReferrerMissing:
		return 6.5
	case CSRFTestOriginMissing:
		return 6.5
	default:
		return 6.5
	}
}

// calculateConfidence calculates confidence level for the vulnerability
func (m *CSRFModule) calculateConfidence(testType CSRFTestType, evidence map[string]interface{}) core.ConfidenceLevel {
	confidence := 0.5 // Base confidence

	// Increase confidence based on evidence
	if _, exists := evidence["both_requests_successful"]; exists {
		confidence += 0.4
	}

	if _, exists := evidence["csrf_token_not_required"]; exists {
		confidence += 0.3
	}

	if _, exists := evidence["invalid_token_accepted"]; exists {
		confidence += 0.3
	}

	// Decrease confidence if CSRF protection is detected
	if _, exists := evidence["potential_csrf_protection"]; exists {
		confidence -= 0.4
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

// getRemediation returns remediation advice based on test type
func (m *CSRFModule) getRemediation(testType CSRFTestType) string {
	switch testType {
	case CSRFTestTokenMissing:
		return "Implement CSRF tokens for all state-changing requests. Use a cryptographically secure random token that is tied to the user's session."
	case CSRFTestTokenInvalid:
		return "Ensure CSRF tokens are properly validated on the server side. Reject requests with invalid or missing tokens."
	case CSRFTestReferrerMissing:
		return "Validate the Referer header to ensure requests originate from your application. However, prefer CSRF tokens as the primary protection."
	case CSRFTestOriginMissing:
		return "Validate the Origin header to ensure requests originate from trusted domains. Combine with CSRF tokens for comprehensive protection."
	default:
		return "Implement comprehensive CSRF protection including tokens, origin validation, and SameSite cookie attributes."
	}
}

// enhanceWithAI enhances the vulnerability with AI analysis
func (m *CSRFModule) enhanceWithAI(ctx context.Context, vuln *core.Vulnerability) {
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

// findCSRFToken finds CSRF token in request body or headers
func (m *CSRFModule) findCSRFToken(headers map[string]string, body []byte) (string, string) {
	// Common CSRF token names
	tokenNames := []string{
		"csrf_token", "csrftoken", "_token", "authenticity_token",
		"csrf", "_csrf", "token", "xsrf_token", "_xsrf",
	}

	// Check headers
	for _, tokenName := range tokenNames {
		if value, exists := headers[tokenName]; exists {
			return tokenName, value
		}
		if value, exists := headers[strings.ToUpper(tokenName)]; exists {
			return tokenName, value
		}
		if value, exists := headers["X-"+strings.ToUpper(tokenName)]; exists {
			return tokenName, value
		}
	}

	// Check body for form data
	bodyStr := string(body)
	for _, tokenName := range tokenNames {
		pattern := fmt.Sprintf(`%s["\']?\s*[:=]\s*["\']?([^"'\s&]+)`, tokenName)
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(bodyStr)
		if len(matches) > 1 {
			return tokenName, matches[1]
		}
	}

	return "", ""
}
