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

// CommandInjectionModule implements command injection vulnerability detection
type CommandInjectionModule struct {
	name        string
	description string
	enabled     bool
	config      *core.ScannerConfig
	aiEngine    *ai.Engine
	logger      *logrus.Logger
	payloads    []CmdInjPayload
	mutex       sync.RWMutex
	progress    float64
}

// CmdInjPayload represents a command injection test payload
type CmdInjPayload struct {
	Payload     string            `json:"payload"`
	Type        CmdInjType        `json:"type"`
	OS          OSType            `json:"os"`
	Description string            `json:"description"`
	Patterns    []string          `json:"patterns"`
	TimeDelay   time.Duration     `json:"time_delay,omitempty"`
	UniqueID    string            `json:"unique_id"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// CmdInjType represents the type of command injection
type CmdInjType int

const (
	CmdInjTypeBlind CmdInjType = iota
	CmdInjTypeTime
	CmdInjTypeError
	CmdInjTypeOutput
	CmdInjTypeOOB // Out-of-band
)

// OSType represents the target operating system
type OSType int

const (
	OSTypeUnix OSType = iota
	OSTypeWindows
	OSTypeBoth
)

// NewCommandInjectionModule creates a new command injection detection module
func NewCommandInjectionModule(config *core.ScannerConfig, aiEngine *ai.Engine, logger *logrus.Logger) *CommandInjectionModule {
	module := &CommandInjectionModule{
		name:        "command_injection",
		description: "Detects OS command injection vulnerabilities",
		enabled:     true,
		config:      config,
		aiEngine:    aiEngine,
		logger:      logger,
	}

	module.initializePayloads()
	return module
}

// Name returns the module name
func (m *CommandInjectionModule) Name() string {
	return m.name
}

// Description returns the module description
func (m *CommandInjectionModule) Description() string {
	return m.description
}

// Enabled returns whether the module is enabled
func (m *CommandInjectionModule) Enabled() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.enabled
}

// SetEnabled sets the module enabled state
func (m *CommandInjectionModule) SetEnabled(enabled bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.enabled = enabled
}

// GetProgress returns the current scan progress
func (m *CommandInjectionModule) GetProgress() float64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.progress
}

// Configure configures the module with provided settings
func (m *CommandInjectionModule) Configure(config map[string]interface{}) error {
	// TODO: Implement module-specific configuration
	return nil
}

// Scan performs command injection vulnerability detection
func (m *CommandInjectionModule) Scan(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
	m.mutex.Lock()
	m.progress = 0.0
	m.mutex.Unlock()

	defer func() {
		m.mutex.Lock()
		m.progress = 100.0
		m.mutex.Unlock()
	}()

	var vulnerabilities []*core.Vulnerability

	m.logger.Debugf("Starting command injection scan for: %s", target.URL)

	// Test URL parameters
	if urlVulns, err := m.testURLParameters(ctx, target); err == nil {
		vulnerabilities = append(vulnerabilities, urlVulns...)
	}

	// Update progress
	m.mutex.Lock()
	m.progress = 33.0
	m.mutex.Unlock()

	// Test POST parameters
	if postVulns, err := m.testPOSTParameters(ctx, target); err == nil {
		vulnerabilities = append(vulnerabilities, postVulns...)
	}

	// Update progress
	m.mutex.Lock()
	m.progress = 66.0
	m.mutex.Unlock()

	// Test headers
	if headerVulns, err := m.testHeaders(ctx, target); err == nil {
		vulnerabilities = append(vulnerabilities, headerVulns...)
	}

	m.logger.Debugf("Command injection scan completed for: %s, found %d vulnerabilities",
		target.URL, len(vulnerabilities))

	return vulnerabilities, nil
}

// testURLParameters tests URL parameters for command injection
func (m *CommandInjectionModule) testURLParameters(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
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

// testPOSTParameters tests POST parameters for command injection
func (m *CommandInjectionModule) testPOSTParameters(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
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

// testHeaders tests HTTP headers for command injection
func (m *CommandInjectionModule) testHeaders(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error) {
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

// testParameter tests a specific parameter with a command injection payload
func (m *CommandInjectionModule) testParameter(ctx context.Context, target *ScanTarget, param, originalValue string, payload CmdInjPayload, location string) (*core.Vulnerability, error) {
	// Create test request
	testRequest := m.createTestRequest(target, param, originalValue, payload, location)

	// Send request
	startTime := time.Now()
	response, err := m.sendRequest(ctx, testRequest)
	responseTime := time.Since(startTime)

	if err != nil {
		return nil, err
	}

	// Analyze response
	isVulnerable, evidence := m.analyzeResponse(response, payload, responseTime)

	if !isVulnerable {
		return nil, nil
	}

	// Create vulnerability object
	vuln := &core.Vulnerability{
		ID:          generateVulnID(),
		Type:        core.VulnCommandInjection,
		Severity:    core.SeverityHigh,
		Title:       fmt.Sprintf("OS Command Injection in %s parameter '%s'", location, param),
		Description: fmt.Sprintf("OS command injection vulnerability detected in %s parameter '%s'. An attacker can execute arbitrary operating system commands.", location, param),
		Evidence:    fmt.Sprintf("Command injection detected with payload: %s", payload.Payload),
		Parameter:   param,
		Payload:     payload.Payload,
		Location:    core.VulnerabilityLocation(location),
		Confidence:  m.calculateConfidence(payload, evidence),
		Remediation: "Use parameterized commands or input validation. Avoid executing user input as system commands. Implement proper input sanitization and use safe APIs.",
		References: []string{
			"https://owasp.org/www-community/attacks/Command_Injection",
			"https://cwe.mitre.org/data/definitions/78.html",
		},
		CVSSScore:    9.0,
		CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		DiscoveredAt: time.Now(),
		UpdatedAt:    time.Now(),
		Metadata: map[string]interface{}{
			"injection_type":   payload.Type,
			"target_os":        payload.OS,
			"response_time":    responseTime.Milliseconds(),
			"evidence_details": evidence,
		},
	}

	// Enhance with AI if available
	if m.aiEngine != nil {
		m.enhanceWithAI(ctx, vuln)
	}

	return vuln, nil
}

// createTestRequest creates a test request with the command injection payload
func (m *CommandInjectionModule) createTestRequest(target *ScanTarget, param, originalValue string, payload CmdInjPayload, location string) *http.Request {
	// TODO: Implement request creation logic
	// This should modify the appropriate part of the request based on location
	return nil
}

// sendRequest sends a test request and returns the response
func (m *CommandInjectionModule) sendRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := &http.Client{
		Timeout: 30 * time.Second, // Longer timeout for command injection
	}

	return client.Do(req.WithContext(ctx))
}

// analyzeResponse analyzes the response for command injection indicators
func (m *CommandInjectionModule) analyzeResponse(response *http.Response, payload CmdInjPayload, responseTime time.Duration) (bool, map[string]interface{}) {
	evidence := make(map[string]interface{})

	// TODO: Read response body safely
	responseBody := ""

	switch payload.Type {
	case CmdInjTypeTime:
		return m.checkTimeDelay(responseTime, payload, evidence)
	case CmdInjTypeError:
		return m.checkErrorPatterns(responseBody, payload, evidence)
	case CmdInjTypeOutput:
		return m.checkOutputPatterns(responseBody, payload, evidence)
	case CmdInjTypeBlind:
		return m.checkBlindInjection(responseBody, payload, evidence)
	case CmdInjTypeOOB:
		return m.checkOOBInjection(payload, evidence)
	}

	return false, evidence
}

// checkTimeDelay checks for time-based command injection
func (m *CommandInjectionModule) checkTimeDelay(responseTime time.Duration, payload CmdInjPayload, evidence map[string]interface{}) (bool, map[string]interface{}) {
	if payload.TimeDelay > 0 && responseTime >= payload.TimeDelay {
		evidence["expected_delay"] = payload.TimeDelay.Milliseconds()
		evidence["actual_delay"] = responseTime.Milliseconds()
		evidence["time_based"] = true
		return true, evidence
	}

	return false, evidence
}

// checkErrorPatterns checks for command execution error patterns
func (m *CommandInjectionModule) checkErrorPatterns(responseBody string, payload CmdInjPayload, evidence map[string]interface{}) (bool, map[string]interface{}) {
	// Common command execution error patterns
	errorPatterns := []string{
		// Unix/Linux errors
		`sh: .*: command not found`,
		`bash: .*: command not found`,
		`/bin/sh: .*: not found`,
		`Permission denied`,
		`No such file or directory`,

		// Windows errors
		`'.*' is not recognized as an internal or external command`,
		`The system cannot find the file specified`,
		`Access is denied`,
		`The filename, directory name, or volume label syntax is incorrect`,

		// General patterns
		`syntax error`,
		`unexpected token`,
		`command failed`,
	}

	for _, pattern := range errorPatterns {
		if matched, _ := regexp.MatchString(pattern, responseBody); matched {
			evidence["error_pattern"] = pattern
			evidence["error_detected"] = true
			return true, evidence
		}
	}

	// Check for specific payload patterns
	for _, pattern := range payload.Patterns {
		if matched, _ := regexp.MatchString(pattern, responseBody); matched {
			evidence["payload_pattern"] = pattern
			evidence["pattern_matched"] = true
			return true, evidence
		}
	}

	return false, evidence
}

// checkOutputPatterns checks for command output patterns
func (m *CommandInjectionModule) checkOutputPatterns(responseBody string, payload CmdInjPayload, evidence map[string]interface{}) (bool, map[string]interface{}) {
	// Check if unique identifier from payload is in response
	if payload.UniqueID != "" && strings.Contains(responseBody, payload.UniqueID) {
		evidence["unique_id_found"] = payload.UniqueID
		evidence["output_detected"] = true
		return true, evidence
	}

	// Check for common command outputs
	outputPatterns := []string{
		// Unix commands
		`uid=\d+.*gid=\d+`,    // id command
		`\w{3}\s+\w{3}\s+\d+`, // date command
		`total \d+`,           // ls -l command
		`\w+:\w+:\d+:\d+`,     // passwd file format

		// Windows commands
		`Volume in drive \w`, // dir command
		`Directory of .*`,    // dir command
		`\d+ File\(s\)`,      // dir command
		`Microsoft Windows`,  // ver command
	}

	for _, pattern := range outputPatterns {
		if matched, _ := regexp.MatchString(pattern, responseBody); matched {
			evidence["output_pattern"] = pattern
			evidence["command_output"] = true
			return true, evidence
		}
	}

	return false, evidence
}

// checkBlindInjection checks for blind command injection
func (m *CommandInjectionModule) checkBlindInjection(responseBody string, payload CmdInjPayload, evidence map[string]interface{}) (bool, map[string]interface{}) {
	// For blind injection, we would need to make multiple requests
	// and compare responses or use other side-channel methods
	// This is a simplified implementation

	return false, evidence
}

// checkOOBInjection checks for out-of-band command injection
func (m *CommandInjectionModule) checkOOBInjection(payload CmdInjPayload, evidence map[string]interface{}) (bool, map[string]interface{}) {
	// For OOB injection, we would check external systems
	// like DNS logs or HTTP callbacks
	// This is a placeholder implementation

	return false, evidence
}

// calculateConfidence calculates confidence level for the vulnerability
func (m *CommandInjectionModule) calculateConfidence(payload CmdInjPayload, evidence map[string]interface{}) core.ConfidenceLevel {
	confidence := 0.3 // Base confidence

	// Increase confidence based on evidence type
	if _, exists := evidence["time_based"]; exists {
		confidence += 0.4
	}

	if _, exists := evidence["error_detected"]; exists {
		confidence += 0.3
	}

	if _, exists := evidence["output_detected"]; exists {
		confidence += 0.5
	}

	if _, exists := evidence["command_output"]; exists {
		confidence += 0.6
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
func (m *CommandInjectionModule) enhanceWithAI(ctx context.Context, vuln *core.Vulnerability) {
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

// extractPOSTParameters extracts parameters from POST body
func (m *CommandInjectionModule) extractPOSTParameters(body []byte) map[string]string {
	params := make(map[string]string)

	// TODO: Implement POST parameter extraction
	// Handle form-data, JSON, XML, etc.

	return params
}

// initializePayloads initializes command injection test payloads
func (m *CommandInjectionModule) initializePayloads() {
	m.payloads = []CmdInjPayload{
		// Basic command separators - Unix
		{
			Payload:     "; id",
			Type:        CmdInjTypeOutput,
			OS:          OSTypeUnix,
			Description: "Basic semicolon separator with id command",
			Patterns:    []string{`uid=\d+.*gid=\d+`},
			UniqueID:    "uid=",
		},
		{
			Payload:     "| id",
			Type:        CmdInjTypeOutput,
			OS:          OSTypeUnix,
			Description: "Pipe separator with id command",
			Patterns:    []string{`uid=\d+.*gid=\d+`},
			UniqueID:    "uid=",
		},
		{
			Payload:     "&& id",
			Type:        CmdInjTypeOutput,
			OS:          OSTypeUnix,
			Description: "AND operator with id command",
			Patterns:    []string{`uid=\d+.*gid=\d+`},
			UniqueID:    "uid=",
		},
		{
			Payload:     "|| id",
			Type:        CmdInjTypeOutput,
			OS:          OSTypeUnix,
			Description: "OR operator with id command",
			Patterns:    []string{`uid=\d+.*gid=\d+`},
			UniqueID:    "uid=",
		},

		// Basic command separators - Windows
		{
			Payload:     "& whoami",
			Type:        CmdInjTypeOutput,
			OS:          OSTypeWindows,
			Description: "Ampersand separator with whoami command",
			Patterns:    []string{`\w+\\\w+`, `\w+`},
			UniqueID:    "\\",
		},
		{
			Payload:     "| whoami",
			Type:        CmdInjTypeOutput,
			OS:          OSTypeWindows,
			Description: "Pipe separator with whoami command",
			Patterns:    []string{`\w+\\\w+`, `\w+`},
			UniqueID:    "\\",
		},

		// Time-based payloads - Unix
		{
			Payload:     "; sleep 5",
			Type:        CmdInjTypeTime,
			OS:          OSTypeUnix,
			Description: "Sleep command for time delay",
			TimeDelay:   5 * time.Second,
		},
		{
			Payload:     "| sleep 5",
			Type:        CmdInjTypeTime,
			OS:          OSTypeUnix,
			Description: "Pipe with sleep command",
			TimeDelay:   5 * time.Second,
		},

		// Time-based payloads - Windows
		{
			Payload:     "& ping -n 6 127.0.0.1",
			Type:        CmdInjTypeTime,
			OS:          OSTypeWindows,
			Description: "Ping command for time delay",
			TimeDelay:   5 * time.Second,
		},
		{
			Payload:     "| ping -n 6 127.0.0.1",
			Type:        CmdInjTypeTime,
			OS:          OSTypeWindows,
			Description: "Pipe with ping command",
			TimeDelay:   5 * time.Second,
		},

		// Error-based payloads
		{
			Payload:     "; invalidcommand123",
			Type:        CmdInjTypeError,
			OS:          OSTypeBoth,
			Description: "Invalid command to trigger error",
			Patterns:    []string{`command not found`, `not recognized`},
		},
		{
			Payload:     "` invalidcommand123 `",
			Type:        CmdInjTypeError,
			OS:          OSTypeUnix,
			Description: "Backtick injection with invalid command",
			Patterns:    []string{`command not found`, `not recognized`},
		},
		{
			Payload:     "$(invalidcommand123)",
			Type:        CmdInjTypeError,
			OS:          OSTypeUnix,
			Description: "Command substitution with invalid command",
			Patterns:    []string{`command not found`, `not recognized`},
		},

		// File system commands
		{
			Payload:     "; cat /etc/passwd",
			Type:        CmdInjTypeOutput,
			OS:          OSTypeUnix,
			Description: "Read passwd file",
			Patterns:    []string{`root:.*:0:0:`},
			UniqueID:    "root:",
		},
		{
			Payload:     "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
			Type:        CmdInjTypeOutput,
			OS:          OSTypeWindows,
			Description: "Read hosts file",
			Patterns:    []string{`localhost`, `127\.0\.0\.1`},
			UniqueID:    "localhost",
		},

		// Environment variable access
		{
			Payload:     "; echo $PATH",
			Type:        CmdInjTypeOutput,
			OS:          OSTypeUnix,
			Description: "Echo PATH environment variable",
			Patterns:    []string{`/usr/bin`, `/bin`},
			UniqueID:    "/bin",
		},
		{
			Payload:     "& echo %PATH%",
			Type:        CmdInjTypeOutput,
			OS:          OSTypeWindows,
			Description: "Echo PATH environment variable",
			Patterns:    []string{`C:\\`, `Windows`},
			UniqueID:    "Windows",
		},

		// Network commands
		{
			Payload:     "; nslookup google.com",
			Type:        CmdInjTypeOutput,
			OS:          OSTypeBoth,
			Description: "DNS lookup command",
			Patterns:    []string{`Non-authoritative answer`, `Address:`},
			UniqueID:    "google.com",
		},

		// Unique identifier injection for detection
		{
			Payload:     "; echo 'CMDINJECTION_TEST_12345'",
			Type:        CmdInjTypeOutput,
			OS:          OSTypeUnix,
			Description: "Echo unique string for detection",
			Patterns:    []string{`CMDINJECTION_TEST_12345`},
			UniqueID:    "CMDINJECTION_TEST_12345",
		},
		{
			Payload:     "& echo CMDINJECTION_TEST_67890",
			Type:        CmdInjTypeOutput,
			OS:          OSTypeWindows,
			Description: "Echo unique string for detection",
			Patterns:    []string{`CMDINJECTION_TEST_67890`},
			UniqueID:    "CMDINJECTION_TEST_67890",
		},
	}
}
