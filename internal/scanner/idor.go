package scanner

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"vulnora/internal/ai"
	"vulnora/internal/core"
)

// IDORModule implements Insecure Direct Object Reference vulnerability detection
type IDORModule struct {
	name        string
	description string
	enabled     bool
	config      *core.ScannerConfig
	aiEngine    *ai.Engine
	logger      *logrus.Logger
	payloads    []IDORPayload
	mutex       sync.RWMutex
	progress    float64
}

// IDORPayload represents an IDOR test payload
type IDORPayload struct {
	OriginalValue string            `json:"original_value"`
	TestValue     string            `json:"test_value"`
	Type          IDORType          `json:"type"`
	Description   string            `json:"description"`
	Pattern       string            `json:"pattern"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// IDORType represents the type of IDOR test
type IDORType int

const (
	IDORTypeSequential IDORType = iota
	IDORTypeRandom
	IDORTypeGuessable
	IDORTypeAdmin
	IDORTypeNull
	IDORTypeNegative
)

// NewIDORModule creates a new IDOR detection module
func NewIDORModule(config *core.ScannerConfig, aiEngine *ai.Engine, logger *logrus.Logger) *IDORModule {
	module := &IDORModule{
		name:        "idor",
		description: "Detects Insecure Direct Object Reference (IDOR) vulnerabilities",
		enabled:     true,
		config:      config,
		aiEngine:    aiEngine,
		logger:      logger,
	}

	return module
}

// Name returns the module name
func (m *IDORModule) Name() string {
	return m.name
}

// Description returns the module description
func (m *IDORModule) Description() string {
	return m.description
}

// Enabled returns whether the module is enabled
func (m *IDORModule) Enabled() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.enabled
}

// SetEnabled sets the module enabled state
func (m *IDORModule) SetEnabled(enabled bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.enabled = enabled
}

// GetProgress returns the current scan progress
func (m *IDORModule) GetProgress() float64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.progress
}

// Configure configures the module with provided settings
func (m *IDORModule) Configure(config map[string]interface{}) error {
	// TODO: Implement module-specific configuration
	return nil
}

// Scan performs IDOR vulnerability detection
func (m *IDORModule) Scan(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
	m.mutex.Lock()
	m.progress = 0.0
	m.mutex.Unlock()

	defer func() {
		m.mutex.Lock()
		m.progress = 100.0
		m.mutex.Unlock()
	}()

	var vulnerabilities []*core.Vulnerability

	m.logger.Debugf("Starting IDOR scan for: %s", target.URL)

	// Generate test payloads based on original parameters
	m.generatePayloads(target)

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

	m.logger.Debugf("IDOR scan completed for: %s, found %d vulnerabilities",
		target.URL, len(vulnerabilities))

	return vulnerabilities, nil
}

// generatePayloads generates IDOR test payloads based on original values
func (m *IDORModule) generatePayloads(target *ScanTarget) {
	m.payloads = []IDORPayload{}

	// Generate payloads for each parameter
	for param, value := range target.Parameters {
		payloads := m.generatePayloadsForValue(param, value)
		m.payloads = append(m.payloads, payloads...)
	}

	// Generate payloads for POST parameters
	postParams := m.extractPOSTParameters(target.Body)
	for param, value := range postParams {
		payloads := m.generatePayloadsForValue(param, value)
		m.payloads = append(m.payloads, payloads...)
	}
}

// generatePayloadsForValue generates test payloads for a specific parameter value
func (m *IDORModule) generatePayloadsForValue(param, value string) []IDORPayload {
	var payloads []IDORPayload

	// Check if value looks like an ID
	if !m.isIDLikeValue(value) {
		return payloads
	}

	// Sequential tests
	if num, err := strconv.Atoi(value); err == nil {
		// Test adjacent numbers
		payloads = append(payloads, IDORPayload{
			OriginalValue: value,
			TestValue:     strconv.Itoa(num + 1),
			Type:          IDORTypeSequential,
			Description:   "Sequential increment test",
			Pattern:       "increment",
		})

		payloads = append(payloads, IDORPayload{
			OriginalValue: value,
			TestValue:     strconv.Itoa(num - 1),
			Type:          IDORTypeSequential,
			Description:   "Sequential decrement test",
			Pattern:       "decrement",
		})

		// Test negative values
		if num > 0 {
			payloads = append(payloads, IDORPayload{
				OriginalValue: value,
				TestValue:     strconv.Itoa(-num),
				Type:          IDORTypeNegative,
				Description:   "Negative value test",
				Pattern:       "negative",
			})
		}

		// Test zero
		if num != 0 {
			payloads = append(payloads, IDORPayload{
				OriginalValue: value,
				TestValue:     "0",
				Type:          IDORTypeNull,
				Description:   "Zero value test",
				Pattern:       "zero",
			})
		}

		// Test admin-like IDs
		adminIDs := []string{"1", "2", "100", "999", "1000"}
		for _, adminID := range adminIDs {
			if adminID != value {
				payloads = append(payloads, IDORPayload{
					OriginalValue: value,
					TestValue:     adminID,
					Type:          IDORTypeAdmin,
					Description:   "Admin ID test",
					Pattern:       "admin",
				})
			}
		}
	}

	// GUID/UUID tests
	if m.isGUIDLike(value) {
		// Test common GUIDs
		commonGUIDs := []string{
			"00000000-0000-0000-0000-000000000000",
			"11111111-1111-1111-1111-111111111111",
			"12345678-1234-1234-1234-123456789012",
		}

		for _, guid := range commonGUIDs {
			if guid != value {
				payloads = append(payloads, IDORPayload{
					OriginalValue: value,
					TestValue:     guid,
					Type:          IDORTypeGuessable,
					Description:   "Common GUID test",
					Pattern:       "guid",
				})
			}
		}
	}

	// Hash-like tests
	if m.isHashLike(value) {
		// Test null hashes
		nullHashes := []string{
			"00000000000000000000000000000000",         // MD5 null
			"0000000000000000000000000000000000000000", // SHA1 null
		}

		for _, hash := range nullHashes {
			if len(hash) == len(value) && hash != value {
				payloads = append(payloads, IDORPayload{
					OriginalValue: value,
					TestValue:     hash,
					Type:          IDORTypeNull,
					Description:   "Null hash test",
					Pattern:       "null_hash",
				})
			}
		}
	}

	return payloads
}

// testURLParameters tests URL parameters for IDOR
func (m *IDORModule) testURLParameters(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
	var vulnerabilities []*core.Vulnerability

	for _, payload := range m.payloads {
		select {
		case <-ctx.Done():
			return vulnerabilities, ctx.Err()
		default:
		}

		vuln, err := m.testIDORPayload(ctx, target, payload, "url_parameter")
		if err != nil {
			m.logger.Debugf("Error testing IDOR payload: %v", err)
			continue
		}

		if vuln != nil {
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities, nil
}

// testPOSTParameters tests POST parameters for IDOR
func (m *IDORModule) testPOSTParameters(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
	var vulnerabilities []*core.Vulnerability

	for _, payload := range m.payloads {
		select {
		case <-ctx.Done():
			return vulnerabilities, ctx.Err()
		default:
		}

		vuln, err := m.testIDORPayload(ctx, target, payload, "post_parameter")
		if err != nil {
			m.logger.Debugf("Error testing IDOR payload: %v", err)
			continue
		}

		if vuln != nil {
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities, nil
}

// testIDORPayload tests a specific IDOR payload
func (m *IDORModule) testIDORPayload(ctx context.Context, target *ScanTarget, payload IDORPayload, location string) (*core.Vulnerability, error) {
	// Create original request
	originalRequest := m.createTestRequest(target, payload.OriginalValue, location)
	originalResponse, err := m.sendRequest(ctx, originalRequest)
	if err != nil {
		return nil, err
	}

	// Create test request with modified parameter
	testRequest := m.createTestRequest(target, payload.TestValue, location)
	testResponse, err := m.sendRequest(ctx, testRequest)
	if err != nil {
		return nil, err
	}

	// Analyze responses for IDOR
	isVulnerable, evidence := m.analyzeIDORResponse(originalResponse, testResponse, payload)

	if !isVulnerable {
		return nil, nil
	}

	// Create vulnerability object
	vuln := &core.Vulnerability{
		ID:          generateVulnID(),
		Type:        core.VulnIDOR,
		Severity:    core.SeverityHigh,
		Title:       fmt.Sprintf("Insecure Direct Object Reference in %s", location),
		Description: fmt.Sprintf("IDOR vulnerability detected. The application allows access to objects by modifying parameter values without proper authorization checks."),
		Evidence:    fmt.Sprintf("Modified parameter from '%s' to '%s' and received different content", payload.OriginalValue, payload.TestValue),
		Parameter:   "", // Will be set based on which parameter was modified
		Payload:     payload.TestValue,
		Location:    core.VulnerabilityLocation(location),
		Confidence:  m.calculateConfidence(payload, evidence),
		Remediation: "Implement proper authorization checks for object access. Use indirect object references or validate user permissions before allowing access to resources.",
		References: []string{
			"https://owasp.org/www-community/attacks/Insecure_Direct_Object_References",
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		},
		CVSSScore:    7.5,
		CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
		DiscoveredAt: time.Now(),
		UpdatedAt:    time.Now(),
		Metadata: map[string]interface{}{
			"idor_type":        payload.Type,
			"original_value":   payload.OriginalValue,
			"test_value":       payload.TestValue,
			"evidence_details": evidence,
		},
	}

	// Enhance with AI if available
	if m.aiEngine != nil {
		m.enhanceWithAI(ctx, vuln)
	}

	return vuln, nil
}

// createTestRequest creates a test request with modified parameter
func (m *IDORModule) createTestRequest(target *ScanTarget, testValue, location string) *http.Request {
	// TODO: Implement request creation logic
	// This should modify the appropriate parameter based on location
	return nil
}

// sendRequest sends a test request and returns the response
func (m *IDORModule) sendRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	return client.Do(req.WithContext(ctx))
}

// analyzeIDORResponse analyzes responses for IDOR indicators
func (m *IDORModule) analyzeIDORResponse(originalResp, testResp *http.Response, payload IDORPayload) (bool, map[string]interface{}) {
	evidence := make(map[string]interface{})

	// Check status codes
	if originalResp.StatusCode != testResp.StatusCode {
		evidence["status_code_diff"] = map[string]int{
			"original": originalResp.StatusCode,
			"test":     testResp.StatusCode,
		}

		// If test request returns 200 but original was different, likely IDOR
		if testResp.StatusCode == 200 && originalResp.StatusCode != 200 {
			evidence["potential_idor"] = true
			return true, evidence
		}

		// If test request returns 403/401 and original was 200, might indicate proper access control
		if (testResp.StatusCode == 403 || testResp.StatusCode == 401) && originalResp.StatusCode == 200 {
			evidence["access_control_present"] = true
			return false, evidence
		}
	}

	// Check content length differences
	if originalResp.ContentLength != testResp.ContentLength {
		evidence["content_length_diff"] = map[string]int64{
			"original": originalResp.ContentLength,
			"test":     testResp.ContentLength,
		}
	}

	// TODO: Implement response body comparison
	// Check for significant differences in response content

	// Check response headers
	originalCT := originalResp.Header.Get("Content-Type")
	testCT := testResp.Header.Get("Content-Type")
	if originalCT != testCT {
		evidence["content_type_diff"] = map[string]string{
			"original": originalCT,
			"test":     testCT,
		}
	}

	// If responses are substantially similar but parameter was changed, potential IDOR
	if testResp.StatusCode == 200 && originalResp.StatusCode == 200 {
		if testResp.ContentLength > 0 && testResp.ContentLength != originalResp.ContentLength {
			evidence["content_accessible"] = true
			return true, evidence
		}
	}

	return false, evidence
}

// calculateConfidence calculates confidence level for the vulnerability
func (m *IDORModule) calculateConfidence(payload IDORPayload, evidence map[string]interface{}) core.ConfidenceLevel {
	confidence := 0.3 // Base confidence

	// Increase confidence based on evidence
	if _, exists := evidence["potential_idor"]; exists {
		confidence += 0.5
	}

	if _, exists := evidence["content_accessible"]; exists {
		confidence += 0.4
	}

	if _, exists := evidence["status_code_diff"]; exists {
		confidence += 0.2
	}

	if _, exists := evidence["content_length_diff"]; exists {
		confidence += 0.1
	}

	// Decrease confidence if access control is present
	if _, exists := evidence["access_control_present"]; exists {
		confidence -= 0.3
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
func (m *IDORModule) enhanceWithAI(ctx context.Context, vuln *core.Vulnerability) {
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

// isIDLikeValue checks if a value looks like an identifier
func (m *IDORModule) isIDLikeValue(value string) bool {
	// Check for numeric IDs
	if _, err := strconv.Atoi(value); err == nil {
		return true
	}

	// Check for GUID/UUID format
	if m.isGUIDLike(value) {
		return true
	}

	// Check for hash-like strings
	if m.isHashLike(value) {
		return true
	}

	// Check for base64-like strings
	if m.isBase64Like(value) {
		return true
	}

	return false
}

// isGUIDLike checks if value looks like a GUID/UUID
func (m *IDORModule) isGUIDLike(value string) bool {
	guidPattern := `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	matched, _ := regexp.MatchString(guidPattern, value)
	return matched
}

// isHashLike checks if value looks like a hash
func (m *IDORModule) isHashLike(value string) bool {
	// MD5: 32 hex chars
	if len(value) == 32 && m.isHexString(value) {
		return true
	}

	// SHA1: 40 hex chars
	if len(value) == 40 && m.isHexString(value) {
		return true
	}

	// SHA256: 64 hex chars
	if len(value) == 64 && m.isHexString(value) {
		return true
	}

	return false
}

// isBase64Like checks if value looks like base64
func (m *IDORModule) isBase64Like(value string) bool {
	if len(value) < 4 {
		return false
	}

	base64Pattern := `^[A-Za-z0-9+/]*={0,2}$`
	matched, _ := regexp.MatchString(base64Pattern, value)
	return matched && len(value)%4 == 0
}

// isHexString checks if string contains only hex characters
func (m *IDORModule) isHexString(value string) bool {
	hexPattern := `^[0-9a-fA-F]+$`
	matched, _ := regexp.MatchString(hexPattern, value)
	return matched
}

// extractPOSTParameters extracts parameters from POST body
func (m *IDORModule) extractPOSTParameters(body []byte) map[string]string {
	params := make(map[string]string)

	// TODO: Implement POST parameter extraction
	// Handle form-data, JSON, XML, etc.

	return params
}
