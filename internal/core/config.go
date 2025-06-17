package core

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	// Application settings
	App AppConfig `yaml:"app"`

	// Proxy configuration
	Proxy ProxyConfig `yaml:"proxy"`

	// AI configuration
	AI AIConfig `yaml:"ai"`

	// Agent configuration
	Agent AgentConfig `yaml:"agent"`

	// Scanner configuration
	Scanner ScannerConfig `yaml:"scanner"`

	// Database configuration
	Database DatabaseConfig `yaml:"database"`

	// API configuration
	API APIConfig `yaml:"api"`

	// Security configuration
	Security SecurityConfig `yaml:"security"`

	// Logging configuration
	Logging LoggingConfig `yaml:"logging"`
}

// AppConfig contains general application settings
type AppConfig struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Environment string `yaml:"environment"`
	DataDir     string `yaml:"data_dir"`
	PluginDir   string `yaml:"plugin_dir"`
	TempDir     string `yaml:"temp_dir"`
}

// ProxyConfig contains proxy server settings
type ProxyConfig struct {
	Host            string   `yaml:"host"`
	Port            int      `yaml:"port"`
	TLSPort         int      `yaml:"tls_port"`
	CertFile        string   `yaml:"cert_file"`
	KeyFile         string   `yaml:"key_file"`
	UpstreamProxy   string   `yaml:"upstream_proxy"`
	AllowedHosts    []string `yaml:"allowed_hosts"`
	BlockedHosts    []string `yaml:"blocked_hosts"`
	MaxConnections  int      `yaml:"max_connections"`
	RequestTimeout  int      `yaml:"request_timeout"`
	ResponseTimeout int      `yaml:"response_timeout"`
}

// AIConfig contains AI engine settings
type AIConfig struct {
	Provider    string            `yaml:"provider"`
	OllamaURL   string            `yaml:"ollama_url"`
	Model       string            `yaml:"model"`
	MaxTokens   int               `yaml:"max_tokens"`
	Temperature float64           `yaml:"temperature"`
	Timeout     int               `yaml:"timeout"`
	Prompts     map[string]string `yaml:"prompts"`
	KnowledgeDB string            `yaml:"knowledge_db"`
}

// AgentConfig contains agent system settings
type AgentConfig struct {
	Manager ManagerConfig `yaml:"manager"`
	Worker  WorkerConfig  `yaml:"worker"`
}

// ManagerConfig contains agent manager settings
type ManagerConfig struct {
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	TLSEnabled     bool   `yaml:"tls_enabled"`
	CertFile       string `yaml:"cert_file"`
	KeyFile        string `yaml:"key_file"`
	MaxWorkers     int    `yaml:"max_workers"`
	TaskTimeout    int    `yaml:"task_timeout"`
	HealthInterval int    `yaml:"health_interval"`
	RetryAttempts  int    `yaml:"retry_attempts"`
}

// WorkerConfig contains worker agent settings
type WorkerConfig struct {
	ID              string         `yaml:"id"`
	Tags            []string       `yaml:"tags"`
	MaxConcurrency  int            `yaml:"max_concurrency"`
	ResourceLimits  ResourceLimits `yaml:"resource_limits"`
	ReportInterval  int            `yaml:"report_interval"`
	ManagerEndpoint string         `yaml:"manager_endpoint"`
}

// ScannerConfig contains scanner engine settings
type ScannerConfig struct {
	MaxDepth          int                    `yaml:"max_depth"`
	MaxRequests       int                    `yaml:"max_requests"`
	RequestTimeout    int                    `yaml:"request_timeout"`
	DelayBetween      int                    `yaml:"delay_between"`
	MaxConcurrency    int                    `yaml:"max_concurrency"`
	UserAgent         string                 `yaml:"user_agent"`
	FollowRedirects   bool                   `yaml:"follow_redirects"`
	VerifySSL         bool                   `yaml:"verify_ssl"`
	ModuleSettings    map[string]interface{} `yaml:"module_settings"`
	CustomPayloads    []string               `yaml:"custom_payloads"`
	AIAnalysisEnabled bool                   `yaml:"ai_analysis_enabled"`
}

// ResourceLimits defines resource constraints for workers
type ResourceLimits struct {
	MaxMemoryMB int `yaml:"max_memory_mb"`
	MaxCPUUsage int `yaml:"max_cpu_usage"`
	MaxDiskMB   int `yaml:"max_disk_mb"`
}

// DatabaseConfig contains database settings
type DatabaseConfig struct {
	Type         string `yaml:"type"`
	Path         string `yaml:"path"`
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	Name         string `yaml:"name"`
	User         string `yaml:"user"`
	Password     string `yaml:"password"`
	MaxOpenConns int    `yaml:"max_open_conns"`
	MaxIdleConns int    `yaml:"max_idle_conns"`
	SSLMode      string `yaml:"ssl_mode"`
}

// APIConfig contains REST API settings
type APIConfig struct {
	Host           string    `yaml:"host"`
	Port           int       `yaml:"port"`
	TLSEnabled     bool      `yaml:"tls_enabled"`
	CertFile       string    `yaml:"cert_file"`
	KeyFile        string    `yaml:"key_file"`
	AllowedOrigins []string  `yaml:"allowed_origins"`
	AuthEnabled    bool      `yaml:"auth_enabled"`
	JWTSecret      string    `yaml:"jwt_secret"`
	RateLimit      RateLimit `yaml:"rate_limit"`
}

// RateLimit defines API rate limiting settings
type RateLimit struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerMinute int  `yaml:"requests_per_minute"`
	BurstSize         int  `yaml:"burst_size"`
}

// SecurityConfig contains security settings
type SecurityConfig struct {
	TLSMinVersion   string   `yaml:"tls_min_version"`
	AllowedCiphers  []string `yaml:"allowed_ciphers"`
	HSTSEnabled     bool     `yaml:"hsts_enabled"`
	CSPHeader       string   `yaml:"csp_header"`
	PluginSandbox   bool     `yaml:"plugin_sandbox"`
	InputValidation bool     `yaml:"input_validation"`
	EncryptionKey   string   `yaml:"encryption_key"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	File       string `yaml:"file"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
	Compress   bool   `yaml:"compress"`
}

// LoadConfig loads configuration from file
func LoadConfig(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)

	// Set defaults
	setDefaults()

	// Read configuration file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, use defaults
			return getDefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Create necessary directories
	if err := createDirectories(&config); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// App defaults
	viper.SetDefault("app.name", "Vulnora")
	viper.SetDefault("app.version", "1.0.0")
	viper.SetDefault("app.environment", "development")
	viper.SetDefault("app.data_dir", "./data")
	viper.SetDefault("app.plugin_dir", "./plugins")
	viper.SetDefault("app.temp_dir", "./tmp")

	// Proxy defaults
	viper.SetDefault("proxy.host", "127.0.0.1")
	viper.SetDefault("proxy.port", 8080)
	viper.SetDefault("proxy.tls_port", 8443)
	viper.SetDefault("proxy.max_connections", 1000)
	viper.SetDefault("proxy.request_timeout", 30)
	viper.SetDefault("proxy.response_timeout", 30)

	// AI defaults
	viper.SetDefault("ai.provider", "ollama")
	viper.SetDefault("ai.ollama_url", "http://localhost:11434")
	viper.SetDefault("ai.model", "llama2")
	viper.SetDefault("ai.max_tokens", 4096)
	viper.SetDefault("ai.temperature", 0.7)
	viper.SetDefault("ai.timeout", 30)

	// Agent manager defaults
	viper.SetDefault("agent.manager.host", "127.0.0.1")
	viper.SetDefault("agent.manager.port", 9090)
	viper.SetDefault("agent.manager.max_workers", 10)
	viper.SetDefault("agent.manager.task_timeout", 300)
	viper.SetDefault("agent.manager.health_interval", 30)
	viper.SetDefault("agent.manager.retry_attempts", 3)

	// Worker defaults
	viper.SetDefault("agent.worker.max_concurrency", 5)
	viper.SetDefault("agent.worker.resource_limits.max_memory_mb", 1024)
	viper.SetDefault("agent.worker.resource_limits.max_cpu_usage", 80)
	viper.SetDefault("agent.worker.resource_limits.max_disk_mb", 512)
	viper.SetDefault("agent.worker.report_interval", 10)

	// Database defaults
	viper.SetDefault("database.type", "sqlite")
	viper.SetDefault("database.path", "./data/vulnora.db")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)

	// API defaults
	viper.SetDefault("api.host", "127.0.0.1")
	viper.SetDefault("api.port", 8081)
	viper.SetDefault("api.auth_enabled", true)
	viper.SetDefault("api.rate_limit.enabled", true)
	viper.SetDefault("api.rate_limit.requests_per_minute", 100)
	viper.SetDefault("api.rate_limit.burst_size", 10)

	// Security defaults
	viper.SetDefault("security.tls_min_version", "1.2")
	viper.SetDefault("security.hsts_enabled", true)
	viper.SetDefault("security.plugin_sandbox", true)
	viper.SetDefault("security.input_validation", true)

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "file")
	viper.SetDefault("logging.file", "./logs/vulnora.log")
	viper.SetDefault("logging.max_size", 100)
	viper.SetDefault("logging.max_backups", 10)
	viper.SetDefault("logging.max_age", 30)
	viper.SetDefault("logging.compress", true)
}

// getDefaultConfig returns a default configuration
func getDefaultConfig() *Config {
	var config Config
	_ = viper.Unmarshal(&config)
	return &config
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	// Validate proxy configuration
	if config.Proxy.Port < 1 || config.Proxy.Port > 65535 {
		return fmt.Errorf("invalid proxy port: %d", config.Proxy.Port)
	}

	if config.Proxy.TLSPort < 1 || config.Proxy.TLSPort > 65535 {
		return fmt.Errorf("invalid proxy TLS port: %d", config.Proxy.TLSPort)
	}

	// Validate AI configuration
	if config.AI.MaxTokens < 1 {
		return fmt.Errorf("AI max_tokens must be positive")
	}

	if config.AI.Temperature < 0 || config.AI.Temperature > 2 {
		return fmt.Errorf("AI temperature must be between 0 and 2")
	}

	// Validate agent configuration
	if config.Agent.Manager.MaxWorkers < 1 {
		return fmt.Errorf("manager max_workers must be positive")
	}

	if config.Agent.Worker.MaxConcurrency < 1 {
		return fmt.Errorf("worker max_concurrency must be positive")
	}

	// Validate API configuration
	if config.API.Port < 1 || config.API.Port > 65535 {
		return fmt.Errorf("invalid API port: %d", config.API.Port)
	}

	return nil
}

// createDirectories creates necessary directories
func createDirectories(config *Config) error {
	dirs := []string{
		config.App.DataDir,
		config.App.PluginDir,
		config.App.TempDir,
		filepath.Dir(config.Logging.File),
		filepath.Dir(config.Database.Path),
	}

	for _, dir := range dirs {
		if dir == "" {
			continue
		}

		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// GetConfigPath returns the configuration file path
func GetConfigPath(env string) string {
	if env == "" {
		env = os.Getenv("VULNORA_ENV")
		if env == "" {
			env = "development"
		}
	}

	return fmt.Sprintf("configs/%s.yaml", env)
}
