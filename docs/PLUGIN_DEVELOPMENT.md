# Plugin Development Guide

## Overview

Vulnora's plugin system allows you to extend the platform's functionality with custom modules. Plugins can implement various types of functionality including custom scanners, payload generators, interceptors, and more.

## Plugin Types

### 1. Scanner Plugins
Implement custom vulnerability detection logic.

### 2. Interceptor Plugins
Modify requests/responses in real-time.

### 3. Payload Plugins
Generate custom attack payloads.

### 4. Report Plugins
Create custom report formats.

### 5. Extension Plugins
Add new UI components or features.

## Plugin Architecture

```go
// Plugin interface that all plugins must implement
type Plugin interface {
    // Initialize the plugin with configuration
    Initialize(config map[string]interface{}) error
    
    // Get plugin metadata
    GetManifest() *PluginManifest
    
    // Start the plugin
    Start() error
    
    // Stop the plugin
    Stop() error
    
    // Execute plugin functionality
    Execute(ctx context.Context, input interface{}) (interface{}, error)
}
```

## Example: SQL Injection Scanner Plugin

```go
package main

import (
    "context"
    "fmt"
    "regexp"
    "strings"
    
    "vulnora/internal/core"
    "vulnora/internal/plugins"
)

// SQLiScannerPlugin implements a custom SQL injection scanner
type SQLiScannerPlugin struct {
    config   map[string]interface{}
    payloads []string
    patterns []*regexp.Regexp
}

// Initialize sets up the plugin
func (p *SQLiScannerPlugin) Initialize(config map[string]interface{}) error {
    p.config = config
    
    // Load custom payloads
    if payloadFile, ok := config["payloads_file"].(string); ok {
        payloads, err := loadPayloadsFromFile(payloadFile)
        if err != nil {
            return fmt.Errorf("failed to load payloads: %w", err)
        }
        p.payloads = payloads
    }
    
    // Compile error patterns
    errorPatterns := []string{
        `SQL syntax.*MySQL`,
        `Warning.*mysql_.*`,
        `MySQLSyntaxErrorException`,
        `valid MySQL result`,
        `PostgreSQL.*ERROR`,
        `Warning.*pg_.*`,
        `valid PostgreSQL result`,
        `ORA-[0-9][0-9][0-9][0-9]`,
        `Microsoft.*ODBC.*SQL Server`,
        `SQLServer JDBC Driver`,
    }
    
    for _, pattern := range errorPatterns {
        regex, err := regexp.Compile(pattern)
        if err != nil {
            return fmt.Errorf("invalid regex pattern %s: %w", pattern, err)
        }
        p.patterns = append(p.patterns, regex)
    }
    
    return nil
}

// GetManifest returns plugin metadata
func (p *SQLiScannerPlugin) GetManifest() *plugins.PluginManifest {
    return &plugins.PluginManifest{
        Name:        "Custom SQL Injection Scanner",
        Version:     "1.0.0",
        Author:      "Security Team",
        Description: "Advanced SQL injection detection with custom payloads",
        Type:        plugins.PluginTypeScanner,
        Permissions: []string{"network", "database"},
        Configuration: map[string]plugins.PluginConfigField{
            "payloads_file": {
                Type:        "string",
                Description: "Path to custom payloads file",
                Required:    false,
            },
            "time_delay": {
                Type:        "integer",
                Default:     5,
                Description: "Time delay for time-based injection tests",
                Required:    false,
            },
        },
    }
}

// Start initializes plugin resources
func (p *SQLiScannerPlugin) Start() error {
    return nil
}

// Stop cleans up plugin resources
func (p *SQLiScannerPlugin) Stop() error {
    return nil
}

// Execute runs the SQL injection scan
func (p *SQLiScannerPlugin) Execute(ctx context.Context, input interface{}) (interface{}, error) {
    request, ok := input.(*core.RequestResponse)
    if !ok {
        return nil, fmt.Errorf("invalid input type, expected *core.RequestResponse")
    }
    
    vulnerabilities := []core.Vulnerability{}
    
    // Test each parameter with each payload
    parameters := extractParameters(request)
    for paramName, paramValue := range parameters {
        for _, payload := range p.payloads {
            vuln := p.testSQLiPayload(ctx, request, paramName, paramValue, payload)
            if vuln != nil {
                vulnerabilities = append(vulnerabilities, *vuln)
            }
        }
    }
    
    return map[string]interface{}{
        "vulnerabilities": vulnerabilities,
        "tested_payloads": len(p.payloads),
        "tested_parameters": len(parameters),
    }, nil
}

// testSQLiPayload tests a specific payload against a parameter
func (p *SQLiScannerPlugin) testSQLiPayload(ctx context.Context, request *core.RequestResponse, 
    paramName, originalValue, payload string) *core.Vulnerability {
    
    // Create modified request with payload
    modifiedReq := cloneRequest(request)
    injectPayload(modifiedReq, paramName, payload)
    
    // Send the request
    response, err := sendRequest(ctx, modifiedReq)
    if err != nil {
        return nil
    }
    
    // Check for SQL error patterns
    if p.containsSQLError(string(response.ResponseBody)) {
        return &core.Vulnerability{
            Type:        core.VulnSQLInjection,
            Severity:    core.SeverityHigh,
            Title:       "SQL Injection Detected",
            Description: fmt.Sprintf("SQL injection vulnerability found in parameter '%s'", paramName),
            Evidence:    fmt.Sprintf("Payload: %s\nResponse contains SQL error", payload),
            Parameter:   paramName,
            Location:    core.LocationParameter,
            Payload:     payload,
            Confidence:  core.ConfidenceHigh,
            Verified:    true,
        }
    }
    
    // Check for time-based injection
    if strings.Contains(payload, "SLEEP") || strings.Contains(payload, "WAITFOR") {
        if response.Duration.Seconds() > 4.0 { // Assuming 5 second delay payload
            return &core.Vulnerability{
                Type:        core.VulnSQLInjection,
                Severity:    core.SeverityHigh,
                Title:       "Time-Based SQL Injection Detected",
                Description: fmt.Sprintf("Time-based SQL injection vulnerability found in parameter '%s'", paramName),
                Evidence:    fmt.Sprintf("Payload: %s\nResponse time: %.2fs", payload, response.Duration.Seconds()),
                Parameter:   paramName,
                Location:    core.LocationParameter,
                Payload:     payload,
                Confidence:  core.ConfidenceMedium,
                Verified:    true,
            }
        }
    }
    
    return nil
}

// containsSQLError checks if response contains SQL error patterns
func (p *SQLiScannerPlugin) containsSQLError(response string) bool {
    for _, pattern := range p.patterns {
        if pattern.MatchString(response) {
            return true
        }
    }
    return false
}

// Helper functions
func extractParameters(req *core.RequestResponse) map[string]string {
    // Implementation to extract parameters from URL, body, etc.
    params := make(map[string]string)
    // ... implementation details
    return params
}

func cloneRequest(req *core.RequestResponse) *core.RequestResponse {
    // Implementation to clone request
    // ... implementation details
    return &core.RequestResponse{}
}

func injectPayload(req *core.RequestResponse, param, payload string) {
    // Implementation to inject payload into parameter
    // ... implementation details
}

func sendRequest(ctx context.Context, req *core.RequestResponse) (*core.RequestResponse, error) {
    // Implementation to send HTTP request
    // ... implementation details
    return &core.RequestResponse{}, nil
}

func loadPayloadsFromFile(filename string) ([]string, error) {
    // Implementation to load payloads from file
    // ... implementation details
    return []string{}, nil
}

// Plugin entry point
func NewPlugin() plugins.Plugin {
    return &SQLiScannerPlugin{}
}
```

## Example: Custom Payload Generator Plugin

```go
package main

import (
    "context"
    "fmt"
    "math/rand"
    "strings"
    "time"
    
    "vulnora/internal/core"
    "vulnora/internal/plugins"
)

// PayloadMutatorPlugin generates mutated payloads
type PayloadMutatorPlugin struct {
    config        map[string]interface{}
    mutationRules []MutationRule
}

type MutationRule struct {
    Name        string
    Pattern     string
    Replacement string
    Probability float64
}

func (p *PayloadMutatorPlugin) Initialize(config map[string]interface{}) error {
    p.config = config
    
    // Initialize mutation rules
    p.mutationRules = []MutationRule{
        {
            Name:        "Case Variation",
            Pattern:     "SELECT",
            Replacement: "select",
            Probability: 0.3,
        },
        {
            Name:        "Comment Injection",
            Pattern:     " ",
            Replacement: "/**/ ",
            Probability: 0.2,
        },
        {
            Name:        "URL Encoding",
            Pattern:     "'",
            Replacement: "%27",
            Probability: 0.4,
        },
        {
            Name:        "Double Encoding",
            Pattern:     "%",
            Replacement: "%25",
            Probability: 0.1,
        },
    }
    
    return nil
}

func (p *PayloadMutatorPlugin) GetManifest() *plugins.PluginManifest {
    return &plugins.PluginManifest{
        Name:        "Payload Mutator",
        Version:     "1.0.0",
        Author:      "Security Team",
        Description: "Generates mutated payloads for evasion testing",
        Type:        plugins.PluginTypePayload,
        Configuration: map[string]plugins.PluginConfigField{
            "mutation_count": {
                Type:        "integer",
                Default:     10,
                Description: "Number of mutations to generate per payload",
                Required:    false,
            },
        },
    }
}

func (p *PayloadMutatorPlugin) Start() error {
    rand.Seed(time.Now().UnixNano())
    return nil
}

func (p *PayloadMutatorPlugin) Stop() error {
    return nil
}

func (p *PayloadMutatorPlugin) Execute(ctx context.Context, input interface{}) (interface{}, error) {
    inputData, ok := input.(map[string]interface{})
    if !ok {
        return nil, fmt.Errorf("invalid input type")
    }
    
    originalPayload, ok := inputData["payload"].(string)
    if !ok {
        return nil, fmt.Errorf("payload not found in input")
    }
    
    mutationCount := 10
    if count, ok := p.config["mutation_count"].(int); ok {
        mutationCount = count
    }
    
    mutatedPayloads := p.generateMutations(originalPayload, mutationCount)
    
    return map[string]interface{}{
        "original_payload":  originalPayload,
        "mutated_payloads": mutatedPayloads,
        "mutation_count":   len(mutatedPayloads),
    }, nil
}

func (p *PayloadMutatorPlugin) generateMutations(payload string, count int) []string {
    mutations := make([]string, 0, count)
    
    for i := 0; i < count; i++ {
        mutated := payload
        
        // Apply random mutations
        for _, rule := range p.mutationRules {
            if rand.Float64() < rule.Probability {
                mutated = strings.ReplaceAll(mutated, rule.Pattern, rule.Replacement)
            }
        }
        
        // Add random case variations
        if rand.Float64() < 0.3 {
            mutated = p.randomCaseVariation(mutated)
        }
        
        // Add random whitespace variations
        if rand.Float64() < 0.2 {
            mutated = p.addWhitespaceVariations(mutated)
        }
        
        if mutated != payload {
            mutations = append(mutations, mutated)
        }
    }
    
    return mutations
}

func (p *PayloadMutatorPlugin) randomCaseVariation(s string) string {
    result := make([]rune, len(s))
    for i, r := range s {
        if rand.Float64() < 0.5 {
            result[i] = r
        } else {
            if r >= 'a' && r <= 'z' {
                result[i] = r - 32 // Convert to uppercase
            } else if r >= 'A' && r <= 'Z' {
                result[i] = r + 32 // Convert to lowercase
            } else {
                result[i] = r
            }
        }
    }
    return string(result)
}

func (p *PayloadMutatorPlugin) addWhitespaceVariations(s string) string {
    variations := []string{"\t", "\n", "\r", "  ", "\x0b", "\x0c"}
    
    for i, variation := range variations {
        if rand.Float64() < 0.1 {
            s = strings.ReplaceAll(s, " ", variation)
            break
        }
        _ = i
    }
    
    return s
}

func NewPlugin() plugins.Plugin {
    return &PayloadMutatorPlugin{}
}
```

## Plugin Manifest Format

Each plugin must include a `plugin.yaml` manifest file:

```yaml
name: "Custom SQL Injection Scanner"
version: "1.0.0"
author: "Security Team"
description: "Advanced SQL injection detection with custom payloads"
homepage: "https://github.com/vulnora/plugins/sqli-scanner"
license: "MIT"
type: "scanner"
entry_point: "plugin.so"
min_version: "1.0.0"

dependencies:
  - "vulnora-core >= 1.0.0"

permissions:
  - "network"
  - "file_read"
  - "database"

configuration:
  payloads_file:
    type: "string"
    description: "Path to custom payloads file"
    required: false
    default: ""
  
  time_delay:
    type: "integer"
    description: "Time delay for time-based injection tests"
    required: false
    default: 5
    validation: "min:1,max:30"

hooks:
  - "pre_request"
  - "post_response"
  - "vulnerability_found"
```

## Building Plugins

### 1. Go Plugin (Shared Library)
```bash
# Build as Go plugin
go build -buildmode=plugin -o custom-scanner.so plugin.go

# Install plugin
cp custom-scanner.so ~/.vulnora/plugins/
cp plugin.yaml ~/.vulnora/plugins/custom-scanner/
```

### 2. Standalone Executable
```bash
# Build as standalone binary
go build -o custom-scanner plugin.go

# Create plugin wrapper
cat > plugin.yaml << EOF
name: "Custom Scanner"
type: "scanner"
entry_point: "./custom-scanner"
communication: "stdio"
EOF
```

## Plugin API Reference

### Core Interfaces

```go
// Plugin lifecycle management
type Plugin interface {
    Initialize(config map[string]interface{}) error
    Start() error
    Stop() error
    Execute(ctx context.Context, input interface{}) (interface{}, error)
    GetManifest() *PluginManifest
}

// Hook system for event-driven plugins
type HookHandler interface {
    OnPreRequest(req *http.Request) error
    OnPostResponse(resp *http.Response) error
    OnVulnerabilityFound(vuln *Vulnerability) error
}

// Scanner plugin interface
type ScannerPlugin interface {
    Plugin
    Scan(ctx context.Context, target *ScanTarget) (*ScanResult, error)
}

// Payload generator interface
type PayloadPlugin interface {
    Plugin
    GeneratePayloads(vulnType VulnerabilityType, context map[string]interface{}) ([]string, error)
}
```

### Utility Functions

```go
// HTTP utilities
func SendRequest(req *http.Request) (*http.Response, error)
func ModifyRequest(req *http.Request, modifications map[string]string) *http.Request
func ExtractParameters(req *http.Request) map[string]string

// Vulnerability utilities
func CreateVulnerability(vulnType VulnerabilityType, details VulnDetails) *Vulnerability
func CalculateConfidence(indicators []string, response *http.Response) float64

// Logging utilities
func LogInfo(plugin string, message string)
func LogError(plugin string, err error)
func LogDebug(plugin string, message string)
```

## Testing Plugins

```go
func TestSQLiScannerPlugin(t *testing.T) {
    plugin := &SQLiScannerPlugin{}
    
    config := map[string]interface{}{
        "payloads_file": "test_payloads.txt",
        "time_delay":    5,
    }
    
    err := plugin.Initialize(config)
    require.NoError(t, err)
    
    err = plugin.Start()
    require.NoError(t, err)
    
    // Test with vulnerable request
    vulnerableReq := &core.RequestResponse{
        Method: "GET",
        URL:    "http://example.com/user.php?id=1",
        // ... other fields
    }
    
    result, err := plugin.Execute(context.Background(), vulnerableReq)
    require.NoError(t, err)
    
    resultMap := result.(map[string]interface{})
    vulns := resultMap["vulnerabilities"].([]core.Vulnerability)
    
    assert.True(t, len(vulns) > 0)
    assert.Equal(t, core.VulnSQLInjection, vulns[0].Type)
    
    plugin.Stop()
}
```

## Security Considerations

### 1. Sandboxing
- Plugins run in restricted environments
- Limited file system access
- Network access controls
- Resource limits (memory, CPU, time)

### 2. Input Validation
- All plugin inputs are validated
- Output sanitization
- Prevent code injection

### 3. Permission System
- Plugins declare required permissions
- Users approve permission requests
- Runtime permission enforcement

### 4. Code Signing
- Plugins must be signed by trusted authors
- Signature verification during loading
- Revocation list support

## Distribution

### Plugin Repository
```json
{
  "name": "vulnora-plugin-repo",
  "version": "1.0.0",
  "plugins": [
    {
      "id": "sqli-advanced",
      "name": "Advanced SQL Injection Scanner",
      "version": "1.2.0",
      "author": "Security Team",
      "download_url": "https://plugins.vulnora.com/sqli-advanced-1.2.0.tar.gz",
      "checksum": "sha256:...",
      "signature": "...",
      "min_vulnora_version": "1.0.0"
    }
  ]
}
```

### Installation Commands
```bash
# Install from repository
vulnora plugin install sqli-advanced

# Install from file
vulnora plugin install ./custom-plugin.tar.gz

# List installed plugins
vulnora plugin list

# Enable/disable plugins
vulnora plugin enable sqli-advanced
vulnora plugin disable sqli-advanced

# Update plugins
vulnora plugin update
```

This plugin system provides extensive customization capabilities while maintaining security and ease of use.
