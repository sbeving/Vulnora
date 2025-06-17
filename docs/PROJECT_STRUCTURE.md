# Vulnora Project Structure

## Complete Directory Layout

```
vulnora/
├── cmd/                              # Application entry points
│   ├── main.go                       # Main application
│   ├── agent/                        # Agent worker entry point
│   │   └── main.go
│   └── cli/                          # CLI tool entry point
│       └── main.go
│
├── internal/                         # Private application code
│   ├── core/                         # Core business logic
│   │   ├── config.go                 # Configuration management
│   │   ├── session.go                # Session handling
│   │   ├── database.go               # Database connections
│   │   └── types.go                  # Core data types
│   │
│   ├── proxy/                        # HTTP/HTTPS proxy module
│   │   ├── proxy.go                  # Main proxy server
│   │   ├── interceptor.go            # Request/response interception
│   │   ├── certificate.go            # Certificate management
│   │   ├── websocket.go              # WebSocket handling
│   │   └── middleware.go             # Proxy middleware
│   │
│   ├── scanner/                      # Vulnerability scanning engine
│   │   ├── engine.go                 # Main scanning engine
│   │   ├── modules/                  # Scan modules
│   │   │   ├── sqli.go               # SQL injection scanner
│   │   │   ├── xss.go                # XSS scanner
│   │   │   ├── idor.go               # IDOR scanner
│   │   │   ├── rce.go                # RCE scanner
│   │   │   └── custom.go             # Custom vulnerability patterns
│   │   ├── signatures/               # Vulnerability signatures
│   │   │   ├── patterns.yaml         # Detection patterns
│   │   │   └── payloads.yaml         # Test payloads
│   │   └── results.go                # Result processing
│   │
│   ├── ai/                           # AI integration module
│   │   ├── engine.go                 # AI engine interface
│   │   ├── ollama.go                 # Ollama integration
│   │   ├── prompts/                  # AI prompts
│   │   │   ├── vulnerability.go      # Vulnerability analysis prompts
│   │   │   ├── payload.go            # Payload generation prompts
│   │   │   └── exploit.go            # Exploit suggestion prompts
│   │   ├── analyzer.go               # Request/response analysis
│   │   ├── payload_generator.go      # AI payload generation
│   │   └── knowledge_base.go         # Security knowledge base
│   │
│   ├── agents/                       # Agent management system
│   │   ├── manager.go                # Agent manager
│   │   ├── worker.go                 # Worker agent implementation
│   │   ├── registry.go               # Agent registration
│   │   ├── communication.go          # gRPC communication
│   │   ├── task_queue.go             # Task distribution
│   │   └── health.go                 # Health monitoring
│   │
│   ├── gui/                          # GUI implementation (Fyne)
│   │   ├── app.go                    # Main application window
│   │   ├── proxy_tab.go              # Proxy interface
│   │   ├── scanner_tab.go            # Scanner interface
│   │   ├── results_tab.go            # Results viewer
│   │   ├── ai_assistant.go           # AI assistant panel
│   │   ├── settings.go               # Settings dialog
│   │   └── components/               # Reusable UI components
│   │       ├── request_viewer.go     # HTTP request viewer
│   │       ├── response_viewer.go    # HTTP response viewer
│   │       ├── tree_view.go          # Site map tree
│   │       └── log_viewer.go         # Log viewer component
│   │
│   ├── api/                          # REST API server
│   │   ├── server.go                 # API server setup
│   │   ├── handlers/                 # API handlers
│   │   │   ├── proxy.go              # Proxy endpoints
│   │   │   ├── scanner.go            # Scanner endpoints
│   │   │   ├── agents.go             # Agent management endpoints
│   │   │   ├── sessions.go           # Session endpoints
│   │   │   └── reports.go            # Report endpoints
│   │   ├── middleware/               # API middleware
│   │   │   ├── auth.go               # Authentication
│   │   │   ├── cors.go               # CORS handling
│   │   │   ├── logging.go            # Request logging
│   │   │   └── rate_limit.go         # Rate limiting
│   │   └── models/                   # API models
│   │       ├── request.go            # Request models
│   │       └── response.go           # Response models
│   │
│   ├── plugins/                      # Plugin system
│   │   ├── manager.go                # Plugin manager
│   │   ├── loader.go                 # Dynamic plugin loading
│   │   ├── sandbox.go                # Plugin sandboxing
│   │   ├── api.go                    # Plugin API interface
│   │   ├── hooks.go                  # Event hooks system
│   │   └── examples/                 # Example plugins
│   │       ├── custom_scanner.go     # Custom scanner plugin
│   │       └── payload_mutator.go    # Payload mutation plugin
│   │
│   ├── reporting/                    # Report generation
│   │   ├── generator.go              # Report generator
│   │   ├── templates/                # Report templates
│   │   │   ├── html.go               # HTML template
│   │   │   ├── pdf.go                # PDF template
│   │   │   └── json.go               # JSON template
│   │   ├── formatters/               # Output formatters
│   │   │   ├── html.go               # HTML formatter
│   │   │   ├── pdf.go                # PDF formatter
│   │   │   └── json.go               # JSON formatter
│   │   └── ai_insights.go            # AI-generated insights
│   │
│   ├── storage/                      # Data storage layer
│   │   ├── bolt.go                   # BoltDB implementation
│   │   ├── sqlite.go                 # SQLite implementation
│   │   ├── redis.go                  # Redis implementation
│   │   ├── models/                   # Data models
│   │   │   ├── session.go            # Session models
│   │   │   ├── request.go            # Request models
│   │   │   ├── vulnerability.go      # Vulnerability models
│   │   │   └── agent.go              # Agent models
│   │   └── migrations/               # Database migrations
│   │       └── 001_initial.sql
│   │
│   └── utils/                        # Utility functions
│       ├── crypto.go                 # Cryptographic utilities
│       ├── network.go                # Network utilities
│       ├── validation.go             # Input validation
│       ├── logger.go                 # Logging utilities
│       └── helpers.go                # General helpers
│
├── pkg/                              # Public API packages
│   ├── client/                       # API client library
│   │   ├── client.go                 # Main client
│   │   └── types.go                  # Client types
│   └── protocol/                     # gRPC protocol definitions
│       ├── agent.proto               # Agent service protocol
│       ├── scanner.proto             # Scanner service protocol
│       └── generated/                # Generated protobuf code
│           ├── agent.pb.go
│           └── scanner.pb.go
│
├── configs/                          # Configuration files
│   ├── default.yaml                  # Default configuration
│   ├── development.yaml              # Development config
│   ├── production.yaml               # Production config
│   └── docker.yaml                   # Docker config
│
├── deployments/                      # Deployment configurations
│   ├── docker/                       # Docker configurations
│   │   ├── Dockerfile                # Main application
│   │   ├── Dockerfile.agent          # Agent worker
│   │   └── docker-compose.yml        # Multi-service setup
│   ├── kubernetes/                   # Kubernetes manifests
│   │   ├── namespace.yaml
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── configmap.yaml
│   └── systemd/                      # Systemd service files
│       ├── vulnora.service
│       └── vulnora-agent.service
│
├── scripts/                          # Build and utility scripts
│   ├── build.sh                      # Build script
│   ├── test.sh                       # Test script
│   ├── docker-build.sh               # Docker build script
│   ├── generate-certs.sh             # Certificate generation
│   └── install.sh                    # Installation script
│
├── test/                             # Test files
│   ├── integration/                  # Integration tests
│   │   ├── proxy_test.go
│   │   ├── scanner_test.go
│   │   └── agent_test.go
│   ├── fixtures/                     # Test fixtures
│   │   ├── test_requests.json
│   │   └── test_responses.json
│   └── mocks/                        # Mock implementations
│       ├── mock_ai.go
│       └── mock_storage.go
│
├── web/                              # Web console (optional)
│   ├── src/                          # React source code
│   ├── public/                       # Static assets
│   └── dist/                         # Built assets
│
├── assets/                           # Static assets
│   ├── icons/                        # Application icons
│   ├── templates/                    # Document templates
│   └── payloads/                     # Default payloads
│
├── docs/                             # Documentation
│   ├── ARCHITECTURE.md               # Architecture documentation
│   ├── TECHNICAL_DESIGN.md           # Technical design document
│   ├── API.md                        # API documentation
│   ├── PLUGINS.md                    # Plugin development guide
│   ├── DEPLOYMENT.md                 # Deployment guide
│   └── CONTRIBUTING.md               # Contribution guidelines
│
├── examples/                         # Example configurations and scripts
│   ├── plugins/                      # Example plugins
│   ├── configs/                      # Example configurations
│   └── scripts/                      # Example automation scripts
│
├── .github/                          # GitHub specific files
│   ├── workflows/                    # GitHub Actions
│   │   ├── ci.yml                    # Continuous integration
│   │   ├── release.yml               # Release automation
│   │   └── security.yml              # Security scanning
│   ├── ISSUE_TEMPLATE/               # Issue templates
│   └── PULL_REQUEST_TEMPLATE.md      # PR template
│
├── go.mod                            # Go module definition
├── go.sum                            # Go module checksums
├── Makefile                          # Build automation
├── .gitignore                        # Git ignore rules
├── .goreleaser.yml                   # GoReleaser configuration
├── README.md                         # Project README
├── LICENSE                           # Project license
└── CHANGELOG.md                      # Change log

```

## Key Design Principles

### 1. Separation of Concerns
- **cmd/**: Entry points for different execution modes
- **internal/**: Private implementation details
- **pkg/**: Public APIs and reusable components
- **configs/**: Configuration management
- **deployments/**: Infrastructure as code

### 2. Modular Architecture
- Each major feature in its own package
- Clear interfaces between modules
- Plugin-based extensibility
- Agent-based distributed processing

### 3. Scalability Considerations
- Horizontal scaling via agents
- Database sharding capabilities
- Async processing with queues
- Resource pooling and management

### 4. Security by Design
- Input validation at boundaries
- Secure defaults everywhere
- Encrypted communication
- Sandboxed plugin execution

### 5. Testability
- Clear separation of test types
- Mock implementations for testing
- Fixture data for consistent tests
- Integration test environments
