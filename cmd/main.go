package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/widget"
	"fyne.io/fyne/v2/container"
	
	"vulnora/internal/core"
	"vulnora/internal/gui"
	"vulnora/internal/proxy"
	"vulnora/internal/ai"
	"vulnora/internal/agents"
)

const (
	AppName    = "Vulnora"
	AppVersion = "1.0.0"
	AppID      = "com.vulnora.security"
)

func main() {
	var (
		configPath = flag.String("config", "configs/default.yaml", "Configuration file path")
		cliMode    = flag.Bool("cli", false, "Run in CLI mode")
		proxyPort  = flag.Int("proxy-port", 8080, "Proxy server port")
		target     = flag.String("target", "", "Target URL for CLI scanning")
	)
	flag.Parse()

	// Initialize configuration
	config, err := core.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize core components
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if *cliMode {
		runCLIMode(ctx, config, *target)
	} else {
		runGUIMode(ctx, config, *proxyPort)
	}

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\nShutting down Vulnora...")
	cancel()
}

func runCLIMode(ctx context.Context, config *core.Config, target string) {
	if target == "" {
		fmt.Println("Target URL required for CLI mode")
		os.Exit(1)
	}

	fmt.Printf("Starting Vulnora CLI scan against: %s\n", target)
	
	// Initialize AI engine
	aiEngine, err := ai.NewEngine(config.AI)
	if err != nil {
		log.Fatalf("Failed to initialize AI engine: %v", err)
	}

	// Initialize agent manager
	agentManager := agents.NewManager(config.Agents, aiEngine)
	
	// Start scanning
	go func() {
		result, err := agentManager.ScanTarget(ctx, target)
		if err != nil {
			log.Printf("Scan failed: %v", err)
			return
		}
		fmt.Printf("Scan completed. Found %d vulnerabilities\n", len(result.Vulnerabilities))
		for _, vuln := range result.Vulnerabilities {
			fmt.Printf("- %s: %s\n", vuln.Type, vuln.Description)
		}
	}()
}

func runGUIMode(ctx context.Context, config *core.Config, proxyPort int) {
	fmt.Printf("Starting Vulnora GUI mode on proxy port %d\n", proxyPort)

	// Create Fyne application
	myApp := app.NewWithID(AppID)
	myApp.SetMetadata(&app.Metadata{
		Name:    AppName,
		Version: AppVersion,
		Icon:    nil, // TODO: Add icon
	})

	// Initialize core components
	aiEngine, err := ai.NewEngine(config.AI)
	if err != nil {
		log.Fatalf("Failed to initialize AI engine: %v", err)
	}

	proxyServer := proxy.NewServer(config.Proxy, aiEngine)
	agentManager := agents.NewManager(config.Agents, aiEngine)

	// Create main window
	mainWindow := gui.NewMainWindow(myApp, proxyServer, agentManager, aiEngine)
	
	// Start proxy server
	go func() {
		if err := proxyServer.Start(ctx, proxyPort); err != nil {
			log.Printf("Proxy server error: %v", err)
		}
	}()

	// Start agent manager
	go func() {
		if err := agentManager.Start(ctx); err != nil {
			log.Printf("Agent manager error: %v", err)
		}
	}()

	// Show window and run
	mainWindow.ShowAndRun()
}