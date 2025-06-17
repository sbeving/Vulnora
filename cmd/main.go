package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"vulnora/internal/agents"
	"vulnora/internal/ai"
	"vulnora/internal/api"
	"vulnora/internal/core"
	"vulnora/internal/gui"
	"vulnora/internal/proxy"
	"vulnora/internal/scanner"
	"vulnora/internal/storage"
	"vulnora/internal/utils"
)

const (
	AppName    = "Vulnora"
	AppVersion = "1.0.0"
	AppID      = "com.vulnora.security"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func main() {
	var (
		configPath = flag.String("config", "configs/default.yaml", "Configuration file path")
		cliMode    = flag.Bool("cli", false, "Run in CLI mode")
		guiMode    = flag.Bool("gui", true, "Run in GUI mode (default)")
		proxyOnly  = flag.Bool("proxy-only", false, "Run only proxy server")
		apiOnly    = flag.Bool("api-only", false, "Run only API server")
		proxyPort  = flag.Int("proxy-port", 8080, "Proxy server port")
		target     = flag.String("target", "", "Target URL for CLI scanning")
		version    = flag.Bool("version", false, "Show version information")
		verbose    = flag.Bool("verbose", false, "Enable verbose logging")
	)
	flag.Parse()

	// Show version information
	if *version {
		fmt.Printf("%s %s\n", AppName, Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Commit: %s\n", Commit)
		return
	}

	// Initialize configuration
	config, err := core.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Override proxy port if specified
	if *proxyPort != 8080 {
		config.Proxy.Port = *proxyPort
	}

	// Setup logging
	logger := setupLogging(config, *verbose)
	logger.WithFields(logrus.Fields{
		"version":    Version,
		"build_time": BuildTime,
		"commit":     Commit,
	}).Info("Starting Vulnora")

	// Initialize core components
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Initialize storage
	storage, err := initializeStorage(config, logger)
	if err != nil {
		logger.Fatalf("Failed to initialize storage: %v", err)
	}
	defer storage.Close()

	// Initialize AI engine
	aiEngine, err := initializeAI(config, logger)
	if err != nil {
		logger.Warnf("Failed to initialize AI engine: %v", err)
		logger.Info("Continuing without AI capabilities")
	}

	// Initialize proxy
	proxyServer, err := initializeProxy(config, logger)
	if err != nil {
		logger.Fatalf("Failed to initialize proxy: %v", err)
	}

	// Initialize scanner
	scannerEngine := initializeScanner(config, aiEngine, storage, logger)

	// Initialize agent manager
	agentManager, err := initializeAgentManager(config, logger)
	if err != nil {
		logger.Warnf("Failed to initialize agent manager: %v", err)
		logger.Info("Continuing without agent capabilities")
	}

	// Initialize API server
	apiServer, err := initializeAPI(config, proxyServer, scannerEngine, agentManager, storage, logger)
	if err != nil {
		logger.Fatalf("Failed to initialize API server: %v", err)
	}

	// Choose execution mode
	switch {
	case *proxyOnly:
		runProxyOnly(ctx, proxyServer, logger, sigChan)
	case *apiOnly:
		runAPIOnly(ctx, apiServer, logger, sigChan)
	case *cliMode:
		runCLIMode(ctx, scannerEngine, *target, logger)
	case *guiMode:
		runGUIMode(config, logger)
	default:
		runFullMode(ctx, proxyServer, apiServer, agentManager, config, logger, sigChan)
	}

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\nShutting down Vulnora...")
	cancel()
}

// setupLogging configures the logging system
func setupLogging(config *core.Config, verbose bool) *logrus.Logger {
	logger := logrus.New()

	// Set log level
	level := config.Logging.Level
	if verbose {
		level = "debug"
	}

	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logger.SetLevel(logLevel)

	// Set log format
	if config.Logging.Format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	// Set output
	if config.Logging.Output == "file" && config.Logging.File != "" {
		file, err := utils.CreateLogFile(config.Logging.File)
		if err != nil {
			logger.Warn("Failed to open log file, using stdout")
		} else {
			logger.SetOutput(file)
		}
	}

	return logger
}

// initializeStorage sets up the storage system
func initializeStorage(config *core.Config, logger *logrus.Logger) (storage.Storage, error) {
	switch config.Database.Type {
	case "sqlite":
		return storage.NewSQLiteStorage(config.Database.Path)
	case "postgres":
		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			config.Database.Host,
			config.Database.Port,
			config.Database.User,
			config.Database.Password,
			config.Database.Name,
			config.Database.SSLMode)
		return storage.NewPostgreSQLStorage(dsn)
	default:
		return storage.NewSQLiteStorage(config.Database.Path)
	}
}

// initializeAI sets up the AI engine
func initializeAI(config *core.Config, logger *logrus.Logger) (*ai.Engine, error) {
	return ai.NewEngine(&config.AI, logger)
}

// initializeProxy sets up the proxy server
func initializeProxy(config *core.Config, logger *logrus.Logger) (*proxy.Proxy, error) {
	return proxy.NewProxy(&config.Proxy, logger)
}

// initializeScanner sets up the scanner engine
func initializeScanner(config *core.Config, aiEngine *ai.Engine, storage storage.Storage, logger *logrus.Logger) *scanner.Engine {
	return scanner.NewEngine(&config.Scanner, aiEngine, storage, logger)
}

// initializeAgentManager sets up the agent manager
func initializeAgentManager(config *core.Config, logger *logrus.Logger) (*agents.Manager, error) {
	return agents.NewManager(&config.Agent.Manager, logger)
}

// initializeAPI sets up the API server
func initializeAPI(config *core.Config, proxy *proxy.Proxy, scanner *scanner.Engine,
	agentMgr *agents.Manager, storage storage.Storage, logger *logrus.Logger) (*api.Server, error) {
	return api.NewServer(&config.API, proxy, scanner, agentMgr, storage, logger)
}

// runProxyOnly runs only the proxy server
func runProxyOnly(ctx context.Context, proxy *proxy.Proxy, logger *logrus.Logger, sigChan chan os.Signal) {
	logger.Info("Starting in proxy-only mode")

	// Start proxy
	go func() {
		if err := proxy.Start(ctx); err != nil {
			logger.Fatalf("Failed to start proxy: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	logger.Info("Shutdown signal received")

	if err := proxy.Stop(); err != nil {
		logger.Errorf("Error stopping proxy: %v", err)
	}

	logger.Info("Proxy stopped")
}

// runAPIOnly runs only the API server
func runAPIOnly(ctx context.Context, api *api.Server, logger *logrus.Logger, sigChan chan os.Signal) {
	logger.Info("Starting in API-only mode")

	// Start API server
	go func() {
		if err := api.Start(ctx); err != nil {
			logger.Fatalf("Failed to start API server: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	logger.Info("Shutdown signal received")

	if err := api.Stop(); err != nil {
		logger.Errorf("Error stopping API server: %v", err)
	}

	logger.Info("API server stopped")
}

// runCLIMode runs the CLI scanner
func runCLIMode(ctx context.Context, scanner *scanner.Engine, target string, logger *logrus.Logger) {
	logger.Info("Starting in CLI mode")

	if target == "" {
		logger.Fatal("Target URL is required in CLI mode")
	}

	// Create scan target
	scanTarget := &scanner.Target{
		URL:       target,
		Scope:     []string{target},
		SessionID: "cli-session",
	}

	// Run scan
	logger.Infof("Starting scan of %s", target)
	results, err := scanner.ScanTarget(ctx, scanTarget)
	if err != nil {
		logger.Fatalf("Scan failed: %v", err)
	}

	// Display results
	logger.Infof("Scan completed. Found %d vulnerabilities", len(results.Vulnerabilities))
	for _, vuln := range results.Vulnerabilities {
		logger.WithFields(logrus.Fields{
			"type":       vuln.Type,
			"severity":   vuln.Severity,
			"confidence": vuln.Confidence,
		}).Info(vuln.Title)
	}
}

// runGUIMode runs the GUI application
func runGUIMode(config *core.Config, logger *logrus.Logger) {
	logger.Info("Starting in GUI mode")

	app, err := gui.NewApplication(config)
	if err != nil {
		logger.Fatalf("Failed to create GUI application: %v", err)
	}

	app.Run()
}

// runFullMode runs all components
func runFullMode(ctx context.Context, proxy *proxy.Proxy, api *api.Server,
	agentMgr *agents.Manager, config *core.Config, logger *logrus.Logger, sigChan chan os.Signal) {

	logger.Info("Starting in full mode")

	// Start all services
	errChan := make(chan error, 3)

	// Start proxy
	go func() {
		if err := proxy.Start(ctx); err != nil {
			errChan <- fmt.Errorf("proxy error: %w", err)
		}
	}()

	// Start API server
	go func() {
		if err := api.Start(ctx); err != nil {
			errChan <- fmt.Errorf("API server error: %w", err)
		}
	}()

	// Start agent manager
	if agentMgr != nil {
		go func() {
			if err := agentMgr.Start(ctx); err != nil {
				errChan <- fmt.Errorf("agent manager error: %w", err)
			}
		}()
	}

	// Start GUI
	go func() {
		app, err := gui.NewApplication(config)
		if err != nil {
			errChan <- fmt.Errorf("GUI error: %w", err)
			return
		}
		app.Run()
	}()

	logger.WithFields(logrus.Fields{
		"proxy_port": config.Proxy.Port,
		"api_port":   config.API.Port,
	}).Info("All services started")

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Infof("Received signal: %v", sig)
	case err := <-errChan:
		logger.Errorf("Service error: %v", err)
	}

	logger.Info("Shutting down services...")

	// Shutdown all services
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	var shutdownErrors []error

	if err := proxy.Stop(); err != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("proxy shutdown error: %w", err))
	}

	if err := api.Stop(); err != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("API server shutdown error: %w", err))
	}

	if agentMgr != nil {
		if err := agentMgr.Stop(); err != nil {
			shutdownErrors = append(shutdownErrors, fmt.Errorf("agent manager shutdown error: %w", err))
		}
	}

	if len(shutdownErrors) > 0 {
		for _, err := range shutdownErrors {
			logger.Error(err)
		}
	} else {
		logger.Info("All services stopped successfully")
	}
}
