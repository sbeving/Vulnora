package agents

import (
	"context"
	"vulnora/internal/core"
	"github.com/sirupsen/logrus"
)

// Manager manages a pool of worker agents
type Manager struct {
	config   *core.AgentConfig
	logger   *logrus.Logger
	agents   map[string]*Agent
	running  bool
}

// Agent represents a worker agent
type Agent struct {
	ID     string
	Status core.AgentStatus
}

// NewManager creates a new agent manager
func NewManager(config *core.AgentConfig, logger *logrus.Logger) (*Manager, error) {
	return &Manager{
		config: config,
		logger: logger,
		agents: make(map[string]*Agent),
	}, nil
}

// Start starts the agent manager
func (m *Manager) Start(ctx context.Context) error {
	m.running = true
	m.logger.Info("Agent manager started")
	return nil
}

// Stop stops the agent manager
func (m *Manager) Stop() error {
	m.running = false
	m.logger.Info("Agent manager stopped")
	return nil
}

// IsRunning returns whether the manager is running
func (m *Manager) IsRunning() bool {
	return m.running
}
