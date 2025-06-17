package core

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// RequestResponse represents an HTTP request/response pair
type RequestResponse struct {
	ID            string            `json:"id" gorm:"primaryKey"`
	SessionID     string            `json:"session_id" gorm:"index"`
	Timestamp     time.Time         `json:"timestamp"`
	Method        string            `json:"method"`
	URL           string            `json:"url"`
	Host          string            `json:"host" gorm:"index"`
	Path          string            `json:"path"`
	Query         string            `json:"query"`
	RequestHeaders  map[string]string `json:"request_headers" gorm:"type:json"`
	RequestBody   []byte            `json:"request_body"`
	StatusCode    int               `json:"status_code"`
	ResponseHeaders map[string]string `json:"response_headers" gorm:"type:json"`
	ResponseBody  []byte            `json:"response_body"`
	ContentType   string            `json:"content_type"`
	ContentLength int64             `json:"content_length"`
	Duration      time.Duration     `json:"duration"`
	Source        string            `json:"source"` // proxy, scanner, agent
	Tags          []string          `json:"tags" gorm:"type:json"`
	Notes         string            `json:"notes"`
}

// Vulnerability represents a discovered vulnerability
type Vulnerability struct {
	ID             string                 `json:"id" gorm:"primaryKey"`
	SessionID      string                 `json:"session_id" gorm:"index"`
	RequestID      string                 `json:"request_id" gorm:"index"`
	Type           VulnerabilityType      `json:"type"`
	Severity       Severity               `json:"severity"`
	Title          string                 `json:"title"`
	Description    string                 `json:"description"`
	Evidence       string                 `json:"evidence"`
	Remediation    string                 `json:"remediation"`
	References     []string               `json:"references" gorm:"type:json"`
	CVSSScore      float64                `json:"cvss_score"`
	CVSSVector     string                 `json:"cvss_vector"`
	Confidence     ConfidenceLevel        `json:"confidence"`
	Payload        string                 `json:"payload"`
	Parameter      string                 `json:"parameter"`
	Location       VulnerabilityLocation  `json:"location"`
	Verified       bool                   `json:"verified"`
	FalsePositive  bool                   `json:"false_positive"`
	AIGenerated    bool                   `json:"ai_generated"`
	AIConfidence   float64                `json:"ai_confidence"`
	DiscoveredAt   time.Time              `json:"discovered_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	Metadata       map[string]interface{} `json:"metadata" gorm:"type:json"`
}

// Session represents a testing session
type Session struct {
	ID          string                 `json:"id" gorm:"primaryKey"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	TargetURL   string                 `json:"target_url"`
	Scope       []string               `json:"scope" gorm:"type:json"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Status      SessionStatus          `json:"status"`
	Settings    SessionSettings        `json:"settings" gorm:"type:json"`
	Statistics  SessionStatistics      `json:"statistics" gorm:"type:json"`
	Metadata    map[string]interface{} `json:"metadata" gorm:"type:json"`
}

// Agent represents a worker agent
type Agent struct {
	ID             string            `json:"id" gorm:"primaryKey"`
	Name           string            `json:"name"`
	Type           AgentType         `json:"type"`
	Status         AgentStatus       `json:"status"`
	Host           string            `json:"host"`
	Port           int               `json:"port"`
	Version        string            `json:"version"`
	Capabilities   []string          `json:"capabilities" gorm:"type:json"`
	Tags           []string          `json:"tags" gorm:"type:json"`
	LastHeartbeat  time.Time         `json:"last_heartbeat"`
	RegisteredAt   time.Time         `json:"registered_at"`
	ResourceUsage  ResourceUsage     `json:"resource_usage" gorm:"type:json"`
	TaskQueue      []string          `json:"task_queue" gorm:"type:json"`
	Configuration  map[string]interface{} `json:"configuration" gorm:"type:json"`
}

// Task represents a work task for agents
type Task struct {
	ID          string                 `json:"id" gorm:"primaryKey"`
	Type        TaskType               `json:"type"`
	Status      TaskStatus             `json:"status"`
	Priority    TaskPriority           `json:"priority"`
	AgentID     string                 `json:"agent_id" gorm:"index"`
	SessionID   string                 `json:"session_id" gorm:"index"`
	Target      string                 `json:"target"`
	Parameters  map[string]interface{} `json:"parameters" gorm:"type:json"`
	Progress    int                    `json:"progress"`
	Result      TaskResult             `json:"result" gorm:"type:json"`
	Error       string                 `json:"error"`
	CreatedAt   time.Time              `json:"created_at"`
	StartedAt   *time.Time             `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at"`
	Timeout     time.Duration          `json:"timeout"`
	RetryCount  int                    `json:"retry_count"`
	MaxRetries  int                    `json:"max_retries"`
}

// Plugin represents a loaded plugin
type Plugin struct {
	ID          string                 `json:"id" gorm:"primaryKey"`
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Author      string                 `json:"author"`
	Description string                 `json:"description"`
	Type        PluginType             `json:"type"`
	Status      PluginStatus           `json:"status"`
	Path        string                 `json:"path"`
	Manifest    PluginManifest         `json:"manifest" gorm:"type:json"`
	Settings    map[string]interface{} `json:"settings" gorm:"type:json"`
	LoadedAt    time.Time              `json:"loaded_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Enums and supporting types

type VulnerabilityType string

const (
	VulnSQLInjection         VulnerabilityType = "sql_injection"
	VulnXSS                  VulnerabilityType = "xss"
	VulnCSRF                 VulnerabilityType = "csrf"
	VulnIDOR                 VulnerabilityType = "idor"
	VulnRCE                  VulnerabilityType = "rce"
	VulnLFI                  VulnerabilityType = "lfi"
	VulnRFI                  VulnerabilityType = "rfi"
	VulnXXE                  VulnerabilityType = "xxe"
	VulnSSRF                 VulnerabilityType = "ssrf"
	VulnAuthBypass           VulnerabilityType = "auth_bypass"
	VulnInsecureDeserialization VulnerabilityType = "insecure_deserialization"
	VulnSecurityMisconfiguration VulnerabilityType = "security_misconfiguration"
	VulnBrokenAccessControl  VulnerabilityType = "broken_access_control"
	VulnCryptographicFailure VulnerabilityType = "cryptographic_failure"
	VulnInjection            VulnerabilityType = "injection"
	VulnVulnerableComponents VulnerabilityType = "vulnerable_components"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type ConfidenceLevel string

const (
	ConfidenceCertain ConfidenceLevel = "certain"
	ConfidenceHigh    ConfidenceLevel = "high"
	ConfidenceMedium  ConfidenceLevel = "medium"
	ConfidenceLow     ConfidenceLevel = "low"
)

type VulnerabilityLocation string

const (
	LocationURL        VulnerabilityLocation = "url"
	LocationHeader     VulnerabilityLocation = "header"
	LocationBody       VulnerabilityLocation = "body"
	LocationParameter  VulnerabilityLocation = "parameter"
	LocationCookie     VulnerabilityLocation = "cookie"
	LocationPath       VulnerabilityLocation = "path"
)

type SessionStatus string

const (
	SessionStatusActive    SessionStatus = "active"
	SessionStatusPaused    SessionStatus = "paused"
	SessionStatusCompleted SessionStatus = "completed"
	SessionStatusArchived  SessionStatus = "archived"
)

type AgentType string

const (
	AgentTypeScanner     AgentType = "scanner"
	AgentTypeRecon       AgentType = "recon"
	AgentTypeExploiter   AgentType = "exploiter"
	AgentTypeReporter    AgentType = "reporter"
	AgentTypeCustom      AgentType = "custom"
)

type AgentStatus string

const (
	AgentStatusOnline   AgentStatus = "online"
	AgentStatusOffline  AgentStatus = "offline"
	AgentStatusBusy     AgentStatus = "busy"
	AgentStatusError    AgentStatus = "error"
)

type TaskType string

const (
	TaskTypeScan      TaskType = "scan"
	TaskTypeRecon     TaskType = "recon"
	TaskTypeExploit   TaskType = "exploit"
	TaskTypeReport    TaskType = "report"
	TaskTypeCustom    TaskType = "custom"
)

type TaskStatus string

const (
	TaskStatusPending    TaskStatus = "pending"
	TaskStatusRunning    TaskStatus = "running"
	TaskStatusCompleted  TaskStatus = "completed"
	TaskStatusFailed     TaskStatus = "failed"
	TaskStatusCancelled  TaskStatus = "cancelled"
)

type TaskPriority int

const (
	TaskPriorityLow    TaskPriority = 1
	TaskPriorityNormal TaskPriority = 2
	TaskPriorityHigh   TaskPriority = 3
	TaskPriorityCritical TaskPriority = 4
)

type PluginType string

const (
	PluginTypeScanner     PluginType = "scanner"
	PluginTypeIntercept   PluginType = "intercept"
	PluginTypePayload     PluginType = "payload"
	PluginTypeReport      PluginType = "report"
	PluginTypeExtension   PluginType = "extension"
)

type PluginStatus string

const (
	PluginStatusLoaded   PluginStatus = "loaded"
	PluginStatusUnloaded PluginStatus = "unloaded"
	PluginStatusError    PluginStatus = "error"
	PluginStatusDisabled PluginStatus = "disabled"
)

// Supporting struct types

type SessionSettings struct {
	ScanDepth         int               `json:"scan_depth"`
	MaxRequests       int               `json:"max_requests"`
	RequestDelay      time.Duration     `json:"request_delay"`
	UserAgent         string            `json:"user_agent"`
	CookieJar         map[string]string `json:"cookie_jar"`
	Headers           map[string]string `json:"headers"`
	FollowRedirects   bool              `json:"follow_redirects"`
	VerifySSL         bool              `json:"verify_ssl"`
	ProxySettings     ProxySettings     `json:"proxy_settings"`
	AIEnabled         bool              `json:"ai_enabled"`
	AIModel           string            `json:"ai_model"`
	PluginSettings    map[string]interface{} `json:"plugin_settings"`
}

type SessionStatistics struct {
	RequestCount      int            `json:"request_count"`
	ResponseCount     int            `json:"response_count"`
	VulnerabilityCount int           `json:"vulnerability_count"`
	ErrorCount        int            `json:"error_count"`
	AvgResponseTime   time.Duration  `json:"avg_response_time"`
	TotalDataTransfer int64          `json:"total_data_transfer"`
	ScanProgress      float64        `json:"scan_progress"`
	StartTime         time.Time      `json:"start_time"`
	EndTime           *time.Time     `json:"end_time"`
	VulnsBySeverity   map[Severity]int `json:"vulns_by_severity"`
}

type ProxySettings struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Type     string `json:"type"` // http, socks5
}

type ResourceUsage struct {
	CPUPercent    float64   `json:"cpu_percent"`
	MemoryMB      int       `json:"memory_mb"`
	DiskMB        int       `json:"disk_mb"`
	NetworkInMB   int       `json:"network_in_mb"`
	NetworkOutMB  int       `json:"network_out_mb"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type TaskResult struct {
	Success         bool                   `json:"success"`
	Data            map[string]interface{} `json:"data"`
	Vulnerabilities []Vulnerability        `json:"vulnerabilities"`
	Requests        []RequestResponse      `json:"requests"`
	Errors          []string               `json:"errors"`
	Metrics         TaskMetrics            `json:"metrics"`
}

type TaskMetrics struct {
	Duration        time.Duration `json:"duration"`
	RequestsSent    int           `json:"requests_sent"`
	ResponsesReceived int         `json:"responses_received"`
	DataTransferred int64         `json:"data_transferred"`
	VulnsFound      int           `json:"vulns_found"`
}

type PluginManifest struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Author       string                 `json:"author"`
	Description  string                 `json:"description"`
	Homepage     string                 `json:"homepage"`
	License      string                 `json:"license"`
	Type         PluginType             `json:"type"`
	EntryPoint   string                 `json:"entry_point"`
	Dependencies []string               `json:"dependencies"`
	Permissions  []string               `json:"permissions"`
	Configuration map[string]PluginConfigField `json:"configuration"`
	Hooks        []string               `json:"hooks"`
	MinVersion   string                 `json:"min_version"`
}

type PluginConfigField struct {
	Type        string      `json:"type"`
	Default     interface{} `json:"default"`
	Description string      `json:"description"`
	Required    bool        `json:"required"`
	Validation  string      `json:"validation"`
}

// Helper methods

// NewRequestResponse creates a new RequestResponse from an HTTP request and response
func NewRequestResponse(req *http.Request, resp *http.Response, sessionID string) *RequestResponse {
	rr := &RequestResponse{
		ID:        uuid.New().String(),
		SessionID: sessionID,
		Timestamp: time.Now(),
		Method:    req.Method,
		URL:       req.URL.String(),
		Host:      req.Host,
		Path:      req.URL.Path,
		Query:     req.URL.RawQuery,
		Source:    "proxy",
	}

	// Extract request headers
	rr.RequestHeaders = make(map[string]string)
	for k, v := range req.Header {
		if len(v) > 0 {
			rr.RequestHeaders[k] = v[0]
		}
	}

	if resp != nil {
		rr.StatusCode = resp.StatusCode
		rr.ContentType = resp.Header.Get("Content-Type")
		rr.ContentLength = resp.ContentLength

		// Extract response headers
		rr.ResponseHeaders = make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				rr.ResponseHeaders[k] = v[0]
			}
		}
	}

	return rr
}

// NewVulnerability creates a new vulnerability
func NewVulnerability(vulnType VulnerabilityType, severity Severity, title, description string) *Vulnerability {
	return &Vulnerability{
		ID:           uuid.New().String(),
		Type:         vulnType,
		Severity:     severity,
		Title:        title,
		Description:  description,
		Confidence:   ConfidenceMedium,
		DiscoveredAt: time.Now(),
		UpdatedAt:    time.Now(),
		Metadata:     make(map[string]interface{}),
	}
}

// NewSession creates a new session
func NewSession(name, targetURL string) *Session {
	return &Session{
		ID:          uuid.New().String(),
		Name:        name,
		TargetURL:   targetURL,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Status:      SessionStatusActive,
		Scope:       []string{targetURL},
		Settings:    SessionSettings{},
		Statistics:  SessionStatistics{},
		Metadata:    make(map[string]interface{}),
	}
}

// NewAgent creates a new agent
func NewAgent(name string, agentType AgentType, host string, port int) *Agent {
	return &Agent{
		ID:           uuid.New().String(),
		Name:         name,
		Type:         agentType,
		Status:       AgentStatusOffline,
		Host:         host,
		Port:         port,
		RegisteredAt: time.Now(),
		Capabilities: []string{},
		Tags:         []string{},
		TaskQueue:    []string{},
		Configuration: make(map[string]interface{}),
	}
}

// NewTask creates a new task
func NewTask(taskType TaskType, target string, sessionID string) *Task {
	return &Task{
		ID:         uuid.New().String(),
		Type:       taskType,
		Status:     TaskStatusPending,
		Priority:   TaskPriorityNormal,
		SessionID:  sessionID,
		Target:     target,
		Parameters: make(map[string]interface{}),
		CreatedAt:  time.Now(),
		MaxRetries: 3,
	}
}

// JSON marshaling for map fields (GORM compatibility)
func (rr *RequestResponse) MarshalHeaders() ([]byte, error) {
	return json.Marshal(rr.RequestHeaders)
}

func (rr *RequestResponse) UnmarshalHeaders(data []byte) error {
	return json.Unmarshal(data, &rr.RequestHeaders)
}
