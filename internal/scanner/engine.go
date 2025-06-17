package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"vulnora/internal/ai"
	"vulnora/internal/core"
	"vulnora/internal/storage"
)

// Engine represents the vulnerability scanning engine
type Engine struct {
	config   *core.ScannerConfig
	logger   *logrus.Logger
	aiEngine *ai.Engine
	storage  storage.Storage
	modules  map[string]Module
	running  bool
	mutex    sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
}

// Module interface for vulnerability detection modules
type Module interface {
	Name() string
	Description() string
	Enabled() bool
	SetEnabled(bool)
	Scan(ctx context.Context, target *ScanTarget) ([]*core.Vulnerability, error)
	Configure(config map[string]interface{}) error
	GetProgress() float64
}

// ScanTarget represents a target for scanning
type ScanTarget struct {
	ID         string                 `json:"id"`
	URL        string                 `json:"url"`
	Method     string                 `json:"method"`
	Headers    map[string]string      `json:"headers"`
	Body       []byte                 `json:"body"`
	Parameters map[string]string      `json:"parameters"`
	Cookies    map[string]string      `json:"cookies"`
	Context    map[string]interface{} `json:"context"`
	SessionID  string                 `json:"session_id"`
}

// ScanResult represents the result of a scan
type ScanResult struct {
	ID              string                   `json:"id"`
	TargetID        string                   `json:"target_id"`
	SessionID       string                   `json:"session_id"`
	StartTime       time.Time                `json:"start_time"`
	EndTime         time.Time                `json:"end_time"`
	Duration        time.Duration            `json:"duration"`
	Status          ScanStatus               `json:"status"`
	Progress        float64                  `json:"progress"`
	Vulnerabilities []*core.Vulnerability    `json:"vulnerabilities"`
	ModuleResults   map[string]*ModuleResult `json:"module_results"`
	Errors          []string                 `json:"errors"`
	TotalRequests   int                      `json:"total_requests"`
	SuccessfulReqs  int                      `json:"successful_requests"`
	FailedRequests  int                      `json:"failed_requests"`
}

// ModuleResult represents the result from a specific module
type ModuleResult struct {
	ModuleName      string                `json:"module_name"`
	Status          ModuleStatus          `json:"status"`
	StartTime       time.Time             `json:"start_time"`
	EndTime         time.Time             `json:"end_time"`
	Duration        time.Duration         `json:"duration"`
	Vulnerabilities []*core.Vulnerability `json:"vulnerabilities"`
	RequestCount    int                   `json:"request_count"`
	ErrorCount      int                   `json:"error_count"`
	Errors          []string              `json:"errors"`
}

// ScanConfig represents scan configuration
type ScanConfig struct {
	ModuleSettings map[string]map[string]interface{} `json:"module_settings"`
	MaxDepth       int                               `json:"max_depth"`
	MaxRequests    int                               `json:"max_requests"`
	Timeout        time.Duration                     `json:"timeout"`
	Concurrent     int                               `json:"concurrent"`
	DelayBetween   time.Duration                     `json:"delay_between"`
	IncludeModules []string                          `json:"include_modules"`
	ExcludeModules []string                          `json:"exclude_modules"`
	AIAnalysis     bool                              `json:"ai_analysis"`
	CustomPayloads []string                          `json:"custom_payloads"`
}

// Enums
type ScanStatus int

const (
	ScanStatusPending ScanStatus = iota
	ScanStatusRunning
	ScanStatusCompleted
	ScanStatusFailed
	ScanStatusCancelled
)

type ModuleStatus int

const (
	ModuleStatusPending ModuleStatus = iota
	ModuleStatusRunning
	ModuleStatusCompleted
	ModuleStatusFailed
	ModuleStatusSkipped
)

// NewEngine creates a new scanner engine
func NewEngine(config *core.ScannerConfig, aiEngine *ai.Engine, storage storage.Storage, logger *logrus.Logger) *Engine {
	ctx, cancel := context.WithCancel(context.Background())

	engine := &Engine{
		config:   config,
		logger:   logger,
		aiEngine: aiEngine,
		storage:  storage,
		modules:  make(map[string]Module),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Initialize modules
	engine.initializeModules()

	return engine
}

// initializeModules initializes all vulnerability detection modules
func (e *Engine) initializeModules() {
	// SQL Injection module
	sqliModule := NewSQLInjectionModule(e.config, e.aiEngine, e.logger)
	e.modules["sql_injection"] = sqliModule

	// XSS module
	xssModule := NewXSSModule(e.config, e.aiEngine, e.logger)
	e.modules["xss"] = xssModule

	// Command Injection module
	cmdModule := NewCommandInjectionModule(e.config, e.aiEngine, e.logger)
	e.modules["command_injection"] = cmdModule

	// IDOR module
	idorModule := NewIDORModule(e.config, e.aiEngine, e.logger)
	e.modules["idor"] = idorModule

	// Path Traversal module
	pathModule := NewPathTraversalModule(e.config, e.aiEngine, e.logger)
	e.modules["path_traversal"] = pathModule

	// CSRF module
	csrfModule := NewCSRFModule(e.config, e.aiEngine, e.logger)
	e.modules["csrf"] = csrfModule

	e.logger.Infof("Initialized %d scanner modules", len(e.modules))
}

// ScanTarget scans a single target
func (e *Engine) ScanTarget(ctx context.Context, target *ScanTarget, config *ScanConfig) (*ScanResult, error) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	if !e.running {
		return nil, fmt.Errorf("scanner engine is not running")
	}

	result := &ScanResult{
		ID:            target.ID,
		TargetID:      target.ID,
		SessionID:     target.SessionID,
		StartTime:     time.Now(),
		Status:        ScanStatusRunning,
		ModuleResults: make(map[string]*ModuleResult),
	}

	e.logger.Infof("Starting scan for target: %s", target.URL)

	// Run modules concurrently
	var wg sync.WaitGroup
	resultChan := make(chan *ModuleResult, len(e.modules))
	errorChan := make(chan error, len(e.modules))

	for name, module := range e.modules {
		if !e.shouldRunModule(name, config) {
			continue
		}

		wg.Add(1)
		go func(moduleName string, mod Module) {
			defer wg.Done()

			moduleResult := &ModuleResult{
				ModuleName: moduleName,
				Status:     ModuleStatusRunning,
				StartTime:  time.Now(),
			}

			vulnerabilities, err := mod.Scan(ctx, target)
			moduleResult.EndTime = time.Now()
			moduleResult.Duration = moduleResult.EndTime.Sub(moduleResult.StartTime)

			if err != nil {
				moduleResult.Status = ModuleStatusFailed
				moduleResult.Errors = append(moduleResult.Errors, err.Error())
				errorChan <- fmt.Errorf("module %s failed: %w", moduleName, err)
			} else {
				moduleResult.Status = ModuleStatusCompleted
				moduleResult.Vulnerabilities = vulnerabilities
			}

			resultChan <- moduleResult
		}(name, module)
	}

	// Close channels when done
	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
	}()

	// Collect results
	var allVulns []*core.Vulnerability
	for moduleResult := range resultChan {
		result.ModuleResults[moduleResult.ModuleName] = moduleResult
		allVulns = append(allVulns, moduleResult.Vulnerabilities...)

		if len(moduleResult.Errors) > 0 {
			result.Errors = append(result.Errors, moduleResult.Errors...)
		}
	}

	// Collect errors
	for err := range errorChan {
		e.logger.Error(err)
	}

	// AI analysis if enabled
	if config.AIAnalysis && e.aiEngine != nil {
		e.enhanceWithAI(ctx, target, allVulns)
	}

	// Finalize result
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Vulnerabilities = allVulns
	result.Status = ScanStatusCompleted
	result.Progress = 100.0

	// Store result
	// TODO: Store scan result when storage interface is updated
	// if err := e.storage.StoreScanResult(result); err != nil {
	// 	e.logger.Errorf("Failed to store scan result: %v", err)
	// }

	e.logger.Infof("Scan completed for target: %s, found %d vulnerabilities",
		target.URL, len(allVulns))

	return result, nil
}

// ScanRequest scans an HTTP request/response pair
func (e *Engine) ScanRequest(ctx context.Context, req *core.RequestResponse, config *ScanConfig) (*ScanResult, error) {
	target := &ScanTarget{
		ID:        req.ID,
		URL:       req.URL,
		Method:    req.Method,
		Headers:   req.RequestHeaders,
		Body:      req.RequestBody,
		SessionID: req.SessionID,
		Context:   map[string]interface{}{"response": req},
	}

	// Extract parameters
	target.Parameters = extractParameters(req)
	target.Cookies = extractCookies(req)

	return e.ScanTarget(ctx, target, config)
}

// Start starts the scanner engine
func (e *Engine) Start() error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.running {
		return fmt.Errorf("scanner engine is already running")
	}

	e.running = true
	e.logger.Info("Scanner engine started")

	return nil
}

// Stop stops the scanner engine
func (e *Engine) Stop() error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if !e.running {
		return fmt.Errorf("scanner engine is not running")
	}

	e.cancel()
	e.running = false
	e.logger.Info("Scanner engine stopped")

	return nil
}

// GetModules returns all available modules
func (e *Engine) GetModules() map[string]Module {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	modules := make(map[string]Module)
	for name, module := range e.modules {
		modules[name] = module
	}

	return modules
}

// EnableModule enables a specific module
func (e *Engine) EnableModule(name string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	module, exists := e.modules[name]
	if !exists {
		return fmt.Errorf("module %s not found", name)
	}

	module.SetEnabled(true)
	e.logger.Infof("Module %s enabled", name)

	return nil
}

// DisableModule disables a specific module
func (e *Engine) DisableModule(name string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	module, exists := e.modules[name]
	if !exists {
		return fmt.Errorf("module %s not found", name)
	}

	module.SetEnabled(false)
	e.logger.Infof("Module %s disabled", name)

	return nil
}

// Helper methods

// shouldRunModule determines if a module should be run based on config
func (e *Engine) shouldRunModule(name string, config *ScanConfig) bool {
	module, exists := e.modules[name]
	if !exists || !module.Enabled() {
		return false
	}

	// Check include list
	if len(config.IncludeModules) > 0 {
		included := false
		for _, included_name := range config.IncludeModules {
			if included_name == name {
				included = true
				break
			}
		}
		if !included {
			return false
		}
	}

	// Check exclude list
	for _, excluded_name := range config.ExcludeModules {
		if excluded_name == name {
			return false
		}
	}

	return true
}

// enhanceWithAI uses AI to enhance vulnerability findings
func (e *Engine) enhanceWithAI(ctx context.Context, target *ScanTarget, vulns []*core.Vulnerability) {
	for _, vuln := range vulns {
		// Get AI suggestions for exploitation
		exploits, err := e.aiEngine.SuggestExploits(vuln, make(map[string]interface{}))
		if err != nil {
			e.logger.Errorf("Failed to get AI exploit suggestions: %v", err)
			continue
		}

		// Enhance vulnerability with AI insights
		if len(exploits) > 0 {
			if vuln.Metadata == nil {
				vuln.Metadata = make(map[string]interface{})
			}
			vuln.Metadata["ai_exploits"] = exploits
			vuln.AIGenerated = true
		}
	}
}

// extractParameters extracts parameters from request
func extractParameters(req *core.RequestResponse) map[string]string {
	params := make(map[string]string)

	// TODO: Extract from URL query parameters
	// TODO: Extract from POST body (form data, JSON, etc.)

	return params
}

// extractCookies extracts cookies from request headers
func extractCookies(req *core.RequestResponse) map[string]string {
	cookies := make(map[string]string)

	// TODO: Parse Cookie header

	return cookies
}

// IsRunning returns whether the scanner is running
func (e *Engine) IsRunning() bool {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.running
}

// GetStats returns scanner statistics
func (e *Engine) GetStats() map[string]interface{} {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	stats := map[string]interface{}{
		"running":       e.running,
		"modules_count": len(e.modules),
		"enabled_modules": func() []string {
			var enabled []string
			for name, module := range e.modules {
				if module.Enabled() {
					enabled = append(enabled, name)
				}
			}
			return enabled
		}(),
	}

	return stats
}
