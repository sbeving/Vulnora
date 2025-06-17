package api

import (
	"context"
	"vulnora/internal/core"
	"github.com/sirupsen/logrus"
)

// Server represents the REST API server
type Server struct {
	config  *core.APIConfig
	logger  *logrus.Logger
	running bool
}

// NewServer creates a new API server
func NewServer(config *core.APIConfig, logger *logrus.Logger) (*Server, error) {
	return &Server{
		config: config,
		logger: logger,
	}, nil
}

// Start starts the API server
func (s *Server) Start(ctx context.Context) error {
	s.running = true
	s.logger.Info("API server started")
	return nil
}

// Stop stops the API server
func (s *Server) Stop() error {
	s.running = false
	s.logger.Info("API server stopped")
	return nil
}

// IsRunning returns whether the server is running
func (s *Server) IsRunning() bool {
	return s.running
}
