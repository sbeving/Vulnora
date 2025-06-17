package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"vulnora/internal/core"
)

// Engine represents the AI analysis engine
type Engine struct {
	config    *core.AIConfig
	logger    *logrus.Logger
	client    *http.Client
	prompts   *PromptManager
	knowledge *KnowledgeBase
}

// OllamaRequest represents a request to Ollama API
type OllamaRequest struct {
	Model     string                 `json:"model"`
	Prompt    string                 `json:"prompt"`
	Stream    bool                   `json:"stream"`
	Options   map[string]interface{} `json:"options,omitempty"`
}

// OllamaResponse represents a response from Ollama API
type OllamaResponse struct {
	Model     string    `json:"model"`
	Response  string    `json:"response"`
	Done      bool      `json:"done"`
	Context   []int     `json:"context,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// AnalysisResult represents the result of AI analysis
type AnalysisResult struct {
	Type         string                 `json:"type"`
	Confidence   float64                `json:"confidence"`
	Findings     []Finding              `json:"findings"`
	Suggestions  []string               `json:"suggestions"`
	Payloads     []string               `json:"payloads"`
	Exploits     []ExploitSuggestion    `json:"exploits"`
	Risk         string                 `json:"risk"`
	Metadata     map[string]interface{} `json:"metadata"`
	ProcessingTime time.Duration        `json:"processing_time"`
}

// Finding represents a security finding
type Finding struct {
	Type        core.VulnerabilityType `json:"type"`
	Severity    core.Severity          `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Description string                 `json:"description"`
	Evidence    string                 `json:"evidence"`
	Location    string                 `json:"location"`
	Remediation string                 `json:"remediation"`
	References  []string               `json:"references"`
}

// ExploitSuggestion represents an exploitation suggestion
type ExploitSuggestion struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Difficulty   string   `json:"difficulty"`
	Prerequisites []string `json:"prerequisites"`
	Steps        []string `json:"steps"`
	Payloads     []string `json:"payloads"`
	References   []string `json:"references"`
}

// PromptManager manages AI prompts
type PromptManager struct {
	prompts map[string]string
}

// KnowledgeBase contains vulnerability knowledge
type KnowledgeBase struct {
	vulnerabilities map[core.VulnerabilityType]map[string]interface{}
	exploits        map[core.VulnerabilityType][]string
}

// NewEngine creates a new AI engine instance
func NewEngine(config *core.AIConfig, logger *logrus.Logger) (*Engine, error) {
	engine := &Engine{
		config: config,
		logger: logger,
		client: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
		},
		prompts:   NewPromptManager(),
		knowledge: NewKnowledgeBase(),
	}

	// Test connection to AI provider
	if err := engine.testConnection(); err != nil {
		return nil, fmt.Errorf("failed to connect to AI provider: %w", err)
	}

	return engine, nil
}

// AnalyzeRequest analyzes an HTTP request for vulnerabilities
func (e *Engine) AnalyzeRequest(req *core.RequestResponse) (*AnalysisResult, error) {
	start := time.Now()

	// Build analysis context
	context := e.buildRequestContext(req)

	// Generate analysis prompt
	prompt := e.prompts.GenerateRequestAnalysisPrompt(context)

	// Query AI model
	response, err := e.queryModel(prompt)
	if err != nil {
		return nil, fmt.Errorf("AI analysis failed: %w", err)
	}

	// Parse response
	result, err := e.parseAnalysisResponse(response, "request")
	if err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %w", err)
	}

	result.ProcessingTime = time.Since(start)
	return result, nil
}

// AnalyzeResponse analyzes an HTTP response for vulnerabilities
func (e *Engine) AnalyzeResponse(req *core.RequestResponse) (*AnalysisResult, error) {
	start := time.Now()

	// Build analysis context
	context := e.buildResponseContext(req)

	// Generate analysis prompt
	prompt := e.prompts.GenerateResponseAnalysisPrompt(context)

	// Query AI model
	response, err := e.queryModel(prompt)
	if err != nil {
		return nil, fmt.Errorf("AI analysis failed: %w", err)
	}

	// Parse response
	result, err := e.parseAnalysisResponse(response, "response")
	if err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %w", err)
	}

	result.ProcessingTime = time.Since(start)
	return result, nil
}

// GeneratePayloads generates attack payloads for a specific vulnerability type
func (e *Engine) GeneratePayloads(vulnType core.VulnerabilityType, context map[string]interface{}) ([]string, error) {
	// Build payload generation context
	promptContext := map[string]interface{}{
		"vulnerability_type": string(vulnType),
		"target_context":     context,
		"knowledge_base":     e.knowledge.GetVulnerabilityInfo(vulnType),
	}

	// Generate payload prompt
	prompt := e.prompts.GeneratePayloadPrompt(promptContext)

	// Query AI model
	response, err := e.queryModel(prompt)
	if err != nil {
		return nil, fmt.Errorf("payload generation failed: %w", err)
	}

	// Parse payloads from response
	payloads := e.parsePayloadsFromResponse(response)
	
	// Enhance with knowledge base payloads
	knowledgePayloads := e.knowledge.GetPayloads(vulnType)
	payloads = append(payloads, knowledgePayloads...)

	return e.deduplicatePayloads(payloads), nil
}

// SuggestExploits suggests exploitation techniques for a vulnerability
func (e *Engine) SuggestExploits(vuln *core.Vulnerability, context map[string]interface{}) ([]ExploitSuggestion, error) {
	// Build exploit suggestion context
	promptContext := map[string]interface{}{
		"vulnerability":    vuln,
		"target_context":   context,
		"knowledge_base":   e.knowledge.GetExploitInfo(vuln.Type),
	}

	// Generate exploit prompt
	prompt := e.prompts.GenerateExploitPrompt(promptContext)

	// Query AI model
	response, err := e.queryModel(prompt)
	if err != nil {
		return nil, fmt.Errorf("exploit suggestion failed: %w", err)
	}

	// Parse exploits from response
	exploits, err := e.parseExploitsFromResponse(response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse exploit suggestions: %w", err)
	}

	return exploits, nil
}

// AnalyzeCode analyzes source code for vulnerabilities
func (e *Engine) AnalyzeCode(code string, language string) (*AnalysisResult, error) {
	start := time.Now()

	// Build code analysis context
	context := map[string]interface{}{
		"code":     code,
		"language": language,
		"patterns": e.knowledge.GetCodePatterns(language),
	}

	// Generate code analysis prompt
	prompt := e.prompts.GenerateCodeAnalysisPrompt(context)

	// Query AI model
	response, err := e.queryModel(prompt)
	if err != nil {
		return nil, fmt.Errorf("code analysis failed: %w", err)
	}

	// Parse response
	result, err := e.parseAnalysisResponse(response, "code")
	if err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %w", err)
	}

	result.ProcessingTime = time.Since(start)
	return result, nil
}

// queryModel sends a request to the AI model
func (e *Engine) queryModel(prompt string) (string, error) {
	switch e.config.Provider {
	case "ollama":
		return e.queryOllama(prompt)
	default:
		return "", fmt.Errorf("unsupported AI provider: %s", e.config.Provider)
	}
}

// queryOllama sends a request to Ollama API
func (e *Engine) queryOllama(prompt string) (string, error) {
	req := OllamaRequest{
		Model:  e.config.Model,
		Prompt: prompt,
		Stream: false,
		Options: map[string]interface{}{
			"temperature": e.config.Temperature,
			"num_predict": e.config.MaxTokens,
		},
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", e.config.OllamaURL+"/api/generate", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return ollamaResp.Response, nil
}

// buildRequestContext builds analysis context for a request
func (e *Engine) buildRequestContext(req *core.RequestResponse) map[string]interface{} {
	return map[string]interface{}{
		"method":       req.Method,
		"url":          req.URL,
		"headers":      req.RequestHeaders,
		"body":         string(req.RequestBody),
		"content_type": req.RequestHeaders["Content-Type"],
		"user_agent":   req.RequestHeaders["User-Agent"],
		"host":         req.Host,
		"path":         req.Path,
		"query":        req.Query,
	}
}

// buildResponseContext builds analysis context for a response
func (e *Engine) buildResponseContext(req *core.RequestResponse) map[string]interface{} {
	return map[string]interface{}{
		"request":         e.buildRequestContext(req),
		"status_code":     req.StatusCode,
		"headers":         req.ResponseHeaders,
		"body":            string(req.ResponseBody),
		"content_type":    req.ContentType,
		"content_length":  req.ContentLength,
		"server":          req.ResponseHeaders["Server"],
		"powered_by":      req.ResponseHeaders["X-Powered-By"],
	}
}

// parseAnalysisResponse parses the AI response into structured results
func (e *Engine) parseAnalysisResponse(response string, analysisType string) (*AnalysisResult, error) {
	// Try to parse as JSON first
	var result AnalysisResult
	if err := json.Unmarshal([]byte(response), &result); err == nil {
		result.Type = analysisType
		return &result, nil
	}

	// If not JSON, parse as text
	result = AnalysisResult{
		Type:         analysisType,
		Confidence:   0.5,
		Findings:     []Finding{},
		Suggestions:  []string{},
		Payloads:     []string{},
		Exploits:     []ExploitSuggestion{},
		Risk:         "unknown",
		Metadata:     make(map[string]interface{}),
	}

	// Parse text response for key information
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Look for vulnerability indicators
		if e.containsVulnerabilityIndicators(line) {
			finding := e.parseVulnerabilityFromText(line)
			if finding != nil {
				result.Findings = append(result.Findings, *finding)
			}
		}

		// Look for suggestions
		if strings.Contains(strings.ToLower(line), "suggest") || 
		   strings.Contains(strings.ToLower(line), "recommend") {
			result.Suggestions = append(result.Suggestions, line)
		}

		// Look for payload indicators
		if strings.Contains(strings.ToLower(line), "payload") {
			payload := e.extractPayloadFromText(line)
			if payload != "" {
				result.Payloads = append(result.Payloads, payload)
			}
		}
	}

	// Calculate overall confidence
	if len(result.Findings) > 0 {
		totalConfidence := 0.0
		for _, finding := range result.Findings {
			totalConfidence += finding.Confidence
		}
		result.Confidence = totalConfidence / float64(len(result.Findings))
	}

	return &result, nil
}

// parsePayloadsFromResponse extracts payloads from AI response
func (e *Engine) parsePayloadsFromResponse(response string) []string {
	var payloads []string

	// Try to parse as JSON first
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err == nil {
		if payloadList, ok := jsonResponse["payloads"].([]interface{}); ok {
			for _, p := range payloadList {
				if payload, ok := p.(string); ok {
					payloads = append(payloads, payload)
				}
			}
		}
	}

	// Parse as text
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if payload := e.extractPayloadFromText(line); payload != "" {
			payloads = append(payloads, payload)
		}
	}

	return payloads
}

// parseExploitsFromResponse extracts exploit suggestions from AI response
func (e *Engine) parseExploitsFromResponse(response string) ([]ExploitSuggestion, error) {
	var exploits []ExploitSuggestion

	// Try to parse as JSON first
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err == nil {
		if exploitList, ok := jsonResponse["exploits"].([]interface{}); ok {
			for _, e := range exploitList {
				if exploitMap, ok := e.(map[string]interface{}); ok {
					exploit := ExploitSuggestion{}
					if name, ok := exploitMap["name"].(string); ok {
						exploit.Name = name
					}
					if desc, ok := exploitMap["description"].(string); ok {
						exploit.Description = desc
					}
					if diff, ok := exploitMap["difficulty"].(string); ok {
						exploit.Difficulty = diff
					}
					exploits = append(exploits, exploit)
				}
			}
		}
	}

	// If no JSON exploits found, create basic exploit from text
	if len(exploits) == 0 {
		exploit := ExploitSuggestion{
			Name:        "AI Generated Exploit",
			Description: response,
			Difficulty:  "medium",
		}
		exploits = append(exploits, exploit)
	}

	return exploits, nil
}

// NewPromptManager creates a new prompt manager
func NewPromptManager() *PromptManager {
	return &PromptManager{
		prompts: make(map[string]string),
	}
}

// NewKnowledgeBase creates a new knowledge base
func NewKnowledgeBase() *KnowledgeBase {
	return &KnowledgeBase{
		vulnerabilities: make(map[core.VulnerabilityType]map[string]interface{}),
		exploits:        make(map[core.VulnerabilityType][]string),
	}
}

// GenerateAnalysisPrompt generates a prompt for vulnerability analysis
func (pm *PromptManager) GenerateAnalysisPrompt(context map[string]interface{}) string {
	// TODO: Implement prompt generation
	return "Analyze this for vulnerabilities"
}

// GenerateRequestAnalysisPrompt generates a prompt for request analysis
func (pm *PromptManager) GenerateRequestAnalysisPrompt(context map[string]interface{}) string {
	// TODO: Implement prompt generation
	return "Analyze this HTTP request for vulnerabilities"
}

// GenerateResponseAnalysisPrompt generates a prompt for response analysis
func (pm *PromptManager) GenerateResponseAnalysisPrompt(context map[string]interface{}) string {
	// TODO: Implement prompt generation
	return "Analyze this HTTP response for vulnerabilities"
}

// GeneratePayloadPrompt generates a prompt for payload creation
func (pm *PromptManager) GeneratePayloadPrompt(context map[string]interface{}) string {
	// TODO: Implement prompt generation
	return "Generate payloads for this vulnerability"
}

// GenerateExploitPrompt generates a prompt for exploit suggestions
func (pm *PromptManager) GenerateExploitPrompt(context map[string]interface{}) string {
	// TODO: Implement prompt generation
	return "Suggest exploitation techniques"
}

// GenerateCodeAnalysisPrompt generates a prompt for code analysis
func (pm *PromptManager) GenerateCodeAnalysisPrompt(context map[string]interface{}) string {
	// TODO: Implement prompt generation
	return "Analyze this code for vulnerabilities"
}

// GetVulnerabilityInfo returns vulnerability information
func (kb *KnowledgeBase) GetVulnerabilityInfo(vulnType core.VulnerabilityType) map[string]interface{} {
	if info, exists := kb.vulnerabilities[vulnType]; exists {
		return info
	}
	return make(map[string]interface{})
}

// GetPayloads returns payload information
func (kb *KnowledgeBase) GetPayloads(vulnType core.VulnerabilityType) []string {
	// TODO: Implement
	return []string{}
}

// GetExploitInfo returns exploit information
func (kb *KnowledgeBase) GetExploitInfo(vulnType core.VulnerabilityType) []string {
	if exploits, exists := kb.exploits[vulnType]; exists {
		return exploits
	}
	return []string{}
}

// GetCodePatterns returns code patterns for a language
func (kb *KnowledgeBase) GetCodePatterns(language string) []string {
	// TODO: Implement
	return []string{}
}

// Helper methods

func (e *Engine) containsVulnerabilityIndicators(text string) bool {
	indicators := []string{
		"vulnerable", "vulnerability", "exploit", "injection", "xss", "sql",
		"csrf", "idor", "rce", "lfi", "rfi", "xxe", "ssrf", "security",
	}

	text = strings.ToLower(text)
	for _, indicator := range indicators {
		if strings.Contains(text, indicator) {
			return true
		}
	}
	return false
}

func (e *Engine) parseVulnerabilityFromText(text string) *Finding {
	finding := &Finding{
		Description: text,
		Confidence:  0.5,
		Severity:    core.SeverityMedium,
	}

	text = strings.ToLower(text)

	// Determine vulnerability type
	if strings.Contains(text, "sql") && strings.Contains(text, "injection") {
		finding.Type = core.VulnSQLInjection
	} else if strings.Contains(text, "xss") || strings.Contains(text, "cross") {
		finding.Type = core.VulnXSS
	} else if strings.Contains(text, "csrf") {
		finding.Type = core.VulnCSRF
	} else if strings.Contains(text, "idor") {
		finding.Type = core.VulnIDOR
	} else if strings.Contains(text, "rce") || strings.Contains(text, "command") {
		finding.Type = core.VulnRCE
	}

	// Determine severity
	if strings.Contains(text, "critical") {
		finding.Severity = core.SeverityCritical
	} else if strings.Contains(text, "high") {
		finding.Severity = core.SeverityHigh
	} else if strings.Contains(text, "low") {
		finding.Severity = core.SeverityLow
	}

	return finding
}

func (e *Engine) extractPayloadFromText(text string) string {
	// Look for common payload patterns
	patterns := []string{
		`'`, `"`, `<script>`, `SELECT`, `UNION`, `<img`, `javascript:`,
		`../`, `%00`, `${`, `{{`, `<?php`, `<svg`, `onload=`, `onerror=`,
	}

	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			// Extract the payload part
			if idx := strings.Index(text, pattern); idx != -1 {
				start := idx
				end := len(text)
				
				// Try to find end of payload
				if endIdx := strings.IndexAny(text[idx:], " \t\n\r"); endIdx != -1 {
					end = idx + endIdx
				}
				
				return strings.TrimSpace(text[start:end])
			}
		}
	}

	return ""
}

func (e *Engine) deduplicatePayloads(payloads []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, payload := range payloads {
		payload = strings.TrimSpace(payload)
		if payload != "" && !seen[payload] {
			seen[payload] = true
			result = append(result, payload)
		}
	}

	return result
}

func (e *Engine) testConnection() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test with a simple prompt
	req, err := http.NewRequestWithContext(ctx, "GET", e.config.OllamaURL+"/api/tags", nil)
	if err != nil {
		return err
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("AI provider returned status %d", resp.StatusCode)
	}

	return nil
}
