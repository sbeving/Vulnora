package gui

import (
	"context"
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"vulnora/internal/ai"
	"vulnora/internal/core"
	"vulnora/internal/proxy"
	"vulnora/internal/scanner"
	"vulnora/internal/agents"
	"vulnora/internal/storage"
)

// Application represents the main GUI application
type Application struct {
	app         fyne.App
	window      fyne.Window
	config      *core.Config
	proxy       *proxy.Proxy
	scanner     *scanner.Engine
	aiEngine    *ai.Engine
	agentMgr    *agents.Manager
	storage     storage.Storage
	
	// UI Components
	tabContainer *container.AppTabs
	proxyTab     *ProxyTab
	scannerTab   *ScannerTab
	resultsTab   *ResultsTab
	aiTab        *AIAssistantTab
	settingsTab  *SettingsTab
	
	// Status
	statusBar    *widget.Label
	progressBar  *widget.ProgressBar
	
	// Context
	ctx    context.Context
	cancel context.CancelFunc
}

// NewApplication creates a new GUI application
func NewApplication(config *core.Config) (*Application, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	guiApp := &Application{
		app:    app.NewWithID("com.vulnora.security"),
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}

	// Set up the application
	guiApp.app.SetMetadata(&fyne.AppMetadata{
		ID:      "com.vulnora.security",
		Name:    "Vulnora",
		Version: config.App.Version,
		Icon:    resourceIconPng, // Resource needs to be generated
	})

	// Create main window
	guiApp.window = guiApp.app.NewWindow("Vulnora - Security Testing Platform")
	guiApp.window.Resize(fyne.NewSize(1400, 900))
	guiApp.window.CenterOnScreen()

	// Initialize components
	if err := guiApp.initializeComponents(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}

	// Setup UI
	guiApp.setupUI()

	// Setup window events
	guiApp.setupWindowEvents()

	return guiApp, nil
}

// initializeComponents initializes all backend components
func (a *Application) initializeComponents() error {
	var err error

	// Initialize storage
	a.storage, err = storage.NewSQLiteStorage(a.config.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Initialize AI engine
	a.aiEngine, err = ai.NewEngine(&a.config.AI, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize AI engine: %w", err)
	}

	// Initialize proxy
	a.proxy, err = proxy.NewProxy(&a.config.Proxy, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize proxy: %w", err)
	}

	// Initialize scanner
	a.scanner = scanner.NewEngine(&a.config.Scanner, a.aiEngine, a.storage, nil)

	// Initialize agent manager
	a.agentMgr, err = agents.NewManager(&a.config.Agent.Manager, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize agent manager: %w", err)
	}

	return nil
}

// setupUI creates and arranges the user interface
func (a *Application) setupUI() {
	// Create status bar
	a.statusBar = widget.NewLabel("Ready")
	a.progressBar = widget.NewProgressBar()
	a.progressBar.Hide()

	statusContainer := container.NewBorder(nil, nil, a.statusBar, a.progressBar)

	// Create tabs
	a.createTabs()

	// Create toolbar
	toolbar := a.createToolbar()

	// Create main layout
	content := container.NewBorder(
		toolbar,      // top
		statusContainer, // bottom
		nil,          // left
		nil,          // right
		a.tabContainer, // center
	)

	a.window.SetContent(content)
}

// createTabs creates all application tabs
func (a *Application) createTabs() {
	a.tabContainer = container.NewAppTabs()

	// Proxy tab
	a.proxyTab = NewProxyTab(a.proxy, a.storage, a.aiEngine)
	a.tabContainer.AppendTab("Proxy", a.proxyTab.CreateContent())

	// Scanner tab
	a.scannerTab = NewScannerTab(a.scanner, a.storage, a.agentMgr)
	a.tabContainer.AppendTab("Scanner", a.scannerTab.CreateContent())

	// Results tab
	a.resultsTab = NewResultsTab(a.storage, a.aiEngine)
	a.tabContainer.AppendTab("Results", a.resultsTab.CreateContent())

	// AI Assistant tab
	a.aiTab = NewAIAssistantTab(a.aiEngine, a.storage)
	a.tabContainer.AppendTab("AI Assistant", a.aiTab.CreateContent())

	// Settings tab
	a.settingsTab = NewSettingsTab(a.config, a)
	a.tabContainer.AppendTab("Settings", a.settingsTab.CreateContent())

	// Set proxy tab as default
	a.tabContainer.SetTabLocation(container.TabLocationLeading)
}

// createToolbar creates the application toolbar
func (a *Application) createToolbar() *widget.Toolbar {
	toolbar := widget.NewToolbar(
		widget.NewToolbarAction(theme.DocumentCreateIcon(), func() {
			a.newSession()
		}),
		widget.NewToolbarAction(theme.FolderOpenIcon(), func() {
			a.openSession()
		}),
		widget.NewToolbarAction(theme.DocumentSaveIcon(), func() {
			a.saveSession()
		}),
		widget.NewToolbarSeparator(),
		widget.NewToolbarAction(theme.MediaPlayIcon(), func() {
			a.startProxy()
		}),
		widget.NewToolbarAction(theme.MediaStopIcon(), func() {
			a.stopProxy()
		}),
		widget.NewToolbarSeparator(),
		widget.NewToolbarAction(theme.SearchIcon(), func() {
			a.startScanning()
		}),
		widget.NewToolbarSeparator(),
		widget.NewToolbarAction(theme.SettingsIcon(), func() {
			a.tabContainer.SelectTab("Settings")
		}),
		widget.NewToolbarAction(theme.HelpIcon(), func() {
			a.showHelp()
		}),
	)

	return toolbar
}

// setupWindowEvents sets up window event handlers
func (a *Application) setupWindowEvents() {
	a.window.SetCloseIntercept(func() {
		a.showExitDialog()
	})

	// Set up shortcuts
	a.window.Canvas().SetOnTypedKey(func(key *fyne.KeyEvent) {
		switch key.Name {
		case fyne.KeyF5:
			a.refreshCurrentTab()
		case fyne.KeyF1:
			a.showHelp()
		}
	})
}

// Run starts the GUI application
func (a *Application) Run() {
	// Show splash screen
	a.showSplashScreen()

	// Start background services
	go a.startBackgroundServices()

	// Show main window and run
	a.window.ShowAndRun()
}

// Shutdown gracefully shuts down the application
func (a *Application) Shutdown() {
	a.updateStatus("Shutting down...")

	// Cancel context
	a.cancel()

	// Stop services
	if a.proxy != nil && a.proxy.IsRunning() {
		a.proxy.Stop()
	}

	if a.agentMgr != nil {
		a.agentMgr.Stop()
	}

	// Close storage
	if a.storage != nil {
		a.storage.Close()
	}

	a.updateStatus("Shutdown complete")
}

// startBackgroundServices starts background services
func (a *Application) startBackgroundServices() {
	// Start agent manager
	if a.agentMgr != nil {
		go func() {
			if err := a.agentMgr.Start(a.ctx); err != nil {
				a.showError("Failed to start agent manager", err)
			}
		}()
	}

	// Update status periodically
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				a.updateSystemStatus()
			case <-a.ctx.Done():
				return
			}
		}
	}()
}

// Toolbar action handlers

func (a *Application) newSession() {
	dialog := NewSessionDialog(func(name, target string) {
		session := core.NewSession(name, target)
		if err := a.storage.SaveSession(session); err != nil {
			a.showError("Failed to create session", err)
			return
		}
		a.updateStatus(fmt.Sprintf("Created new session: %s", name))
		a.refreshCurrentTab()
	})
	dialog.Show(a.window)
}

func (a *Application) openSession() {
	sessions, err := a.storage.GetSessions()
	if err != nil {
		a.showError("Failed to load sessions", err)
		return
	}

	dialog := NewOpenSessionDialog(sessions, func(session *core.Session) {
		a.updateStatus(fmt.Sprintf("Opened session: %s", session.Name))
		a.refreshCurrentTab()
	})
	dialog.Show(a.window)
}

func (a *Application) saveSession() {
	a.updateStatus("Session saved")
	// Implementation depends on current session state
}

func (a *Application) startProxy() {
	if a.proxy.IsRunning() {
		a.showInfo("Proxy is already running")
		return
	}

	go func() {
		a.updateStatus("Starting proxy...")
		if err := a.proxy.Start(a.ctx); err != nil {
			a.showError("Failed to start proxy", err)
			return
		}
		a.updateStatus(fmt.Sprintf("Proxy running on port %d", a.config.Proxy.Port))
	}()
}

func (a *Application) stopProxy() {
	if !a.proxy.IsRunning() {
		a.showInfo("Proxy is not running")
		return
	}

	if err := a.proxy.Stop(); err != nil {
		a.showError("Failed to stop proxy", err)
		return
	}
	a.updateStatus("Proxy stopped")
}

func (a *Application) startScanning() {
	if !a.proxy.IsRunning() {
		a.showError("Start proxy first", fmt.Errorf("proxy must be running to scan"))
		return
	}

	a.tabContainer.SelectTab("Scanner")
	a.scannerTab.StartQuickScan()
}

func (a *Application) showHelp() {
	content := widget.NewRichTextFromMarkdown(`# Vulnora Help

## Quick Start
1. **Start Proxy**: Click the play button to start the proxy server
2. **Configure Browser**: Set your browser to use localhost:8080 as HTTP proxy
3. **Browse Target**: Navigate to your target application
4. **Review Requests**: Check the Proxy tab for intercepted requests
5. **Run Scans**: Use the Scanner tab to run automated vulnerability scans
6. **AI Analysis**: Use the AI Assistant for intelligent analysis

## Features
- **HTTP/HTTPS Proxy**: Intercept and modify web traffic
- **AI-Powered Analysis**: Intelligent vulnerability detection
- **Automated Scanning**: Comprehensive security testing
- **Agent-Based Architecture**: Distributed scanning capabilities
- **Plugin System**: Extensible functionality

## Keyboard Shortcuts
- **F5**: Refresh current tab
- **F1**: Show this help
- **Ctrl+N**: New session
- **Ctrl+O**: Open session
- **Ctrl+S**: Save session

## Support
Visit our documentation at: https://github.com/vulnora/vulnora`)

	dialog := NewHelpDialog(content)
	dialog.Show(a.window)
}

// Utility methods

func (a *Application) updateStatus(message string) {
	a.statusBar.SetText(message)
}

func (a *Application) updateSystemStatus() {
	status := "Ready"
	
	if a.proxy.IsRunning() {
		stats := a.proxy.GetStats()
		status = fmt.Sprintf("Proxy: %d requests | Agents: %d active", 
			stats.RequestsHandled, a.agentMgr.GetActiveAgentCount())
	}
	
	a.updateStatus(status)
}

func (a *Application) showProgress(show bool) {
	if show {
		a.progressBar.Show()
	} else {
		a.progressBar.Hide()
	}
}

func (a *Application) setProgress(value float64) {
	a.progressBar.SetValue(value)
}

func (a *Application) refreshCurrentTab() {
	switch a.tabContainer.SelectedText() {
	case "Proxy":
		a.proxyTab.Refresh()
	case "Scanner":
		a.scannerTab.Refresh()
	case "Results":
		a.resultsTab.Refresh()
	case "AI Assistant":
		a.aiTab.Refresh()
	}
}

func (a *Application) showSplashScreen() {
	splash := NewSplashScreen(a.config.App.Version)
	splash.Show(a.window)
	
	// Hide splash after 2 seconds
	time.AfterFunc(2*time.Second, func() {
		splash.Hide()
	})
}

func (a *Application) showExitDialog() {
	dialog := NewConfirmDialog(
		"Exit Vulnora",
		"Are you sure you want to exit? Any unsaved work will be lost.",
		func(confirmed bool) {
			if confirmed {
				a.Shutdown()
				a.app.Quit()
			}
		},
	)
	dialog.Show(a.window)
}

func (a *Application) showError(title string, err error) {
	dialog := NewErrorDialog(title, err.Error())
	dialog.Show(a.window)
}

func (a *Application) showInfo(message string) {
	dialog := NewInfoDialog("Information", message)
	dialog.Show(a.window)
}

// GetWindow returns the main application window
func (a *Application) GetWindow() fyne.Window {
	return a.window
}

// GetConfig returns the application configuration
func (a *Application) GetConfig() *core.Config {
	return a.config
}

// GetStorage returns the storage interface
func (a *Application) GetStorage() storage.Storage {
	return a.storage
}

// Placeholder for resource - this would be generated by fyne bundle
var resourceIconPng = &fyne.StaticResource{
	StaticName:    "icon.png",
	StaticContent: []byte{}, // Icon data would go here
}
