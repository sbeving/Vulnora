# Vulnora Architecture

## 🏗️ High-Level Architecture

Vulnora follows a modular, agent-based architecture designed for scalability and extensibility:

```
┌─────────────────────────────────────────────────────────────────┐
│                        GUI Layer (Fyne)                        │
├─────────────────────────────────────────────────────────────────┤
│                     Application Layer                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │   Proxy     │  │   Scanner   │  │   Intruder  │            │
│  │   Module    │  │   Module    │  │   Module    │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
├─────────────────────────────────────────────────────────────────┤
│                      Core Services                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │  AI Engine  │  │   Agent     │  │   Plugin    │            │
│  │  (Ollama)   │  │  Manager    │  │   System    │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
├─────────────────────────────────────────────────────────────────┤
│                    Communication Layer                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │    gRPC     │  │  WebSocket  │  │   REST API  │            │
│  │   Server    │  │   Server    │  │   Server    │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
├─────────────────────────────────────────────────────────────────┤
│                      Data Layer                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │   SQLite    │  │   BoltDB    │  │   Session   │            │
│  │ (Metadata)  │  │  (Cache)    │  │   Store     │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

## 📂 Directory Structure

```
vulnora/
├── cmd/
│   ├── main.go                 # Main application entry point
│   ├── cli/                    # CLI commands
│   └── agent/                  # Agent worker executable
├── internal/
│   ├── core/                   # Core business logic
│   │   ├── config.go          # Configuration management
│   │   ├── session.go         # Session management
│   │   └── types.go           # Common types and interfaces
│   ├── gui/                    # GUI components (Fyne)
│   │   ├── app.go             # Main application window
│   │   ├── proxy.go           # Proxy interface
│   │   ├── scanner.go         # Scanner interface
│   │   └── intruder.go        # Intruder interface
│   ├── proxy/                  # HTTP proxy implementation
│   │   ├── interceptor.go     # Request/response interception
│   │   ├── history.go         # Request history tracking
│   │   └── modifier.go        # Request/response modification
│   ├── agents/                 # Agent system
│   │   ├── manager.go         # Agent lifecycle management
│   │   ├── worker.go          # Worker node implementation
│   │   └── coordinator.go     # Task coordination
│   ├── ai/                     # AI integration
│   │   ├── engine.go          # AI engine interface
│   │   ├── ollama.go          # Ollama integration
│   │   ├── prompts.go         # Prompt templates
│   │   └── payloads.go        # AI-generated payloads
│   ├── scanner/                # Vulnerability scanning
│   │   ├── engine.go          # Scanning engine
│   │   ├── detectors/         # Vulnerability detectors
│   │   │   ├── sqli.go        # SQL injection detection
│   │   │   ├── xss.go         # XSS detection
│   │   │   └── idor.go        # IDOR detection
│   │   └── reporting.go       # Scan reporting
│   └── plugins/                # Plugin system
│       ├── loader.go          # Plugin loader
│       ├── api.go             # Plugin API
│       └── examples/          # Example plugins
├── pkg/                        # Public API packages
│   ├── models/                # Data models
│   ├── utils/                 # Utility functions
│   └── errors/                # Error definitions
├── api/                        # API definitions
│   ├── grpc/                  # gRPC service definitions
│   ├── rest/                  # REST API handlers
│   └── websocket/             # WebSocket handlers
├── configs/                    # Configuration files
│   ├── default.yaml           # Default configuration
│   └── plugins.yaml           # Plugin configuration
├── docs/                       # Documentation
│   ├── ARCHITECTURE.md        # This file
│   ├── API.md                 # API documentation
│   └── PLUGINS.md             # Plugin development guide
├── scripts/                    # Build and deployment scripts
├── tests/                      # Test files
└── deployments/               # Deployment configurations
    ├── docker/                # Docker configurations
    └── k8s/                   # Kubernetes manifests
```

## 🔄 Agent Communication Flow

```
┌─────────────┐    gRPC/TLS     ┌─────────────┐
│   GUI App   │◄──────────────►│   Manager   │
└─────────────┘                └─────────────┘
                                       │
                               ┌───────┼───────┐
                               │       │       │
                    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
                    │  Scanner    │ │  Fuzzer     │ │  Recon      │
                    │  Agent      │ │  Agent      │ │  Agent      │
                    └─────────────┘ └─────────────┘ └─────────────┘
                           │               │               │
                           └───────────────┼───────────────┘
                                           │
                                  ┌─────────────┐
                                  │ AI Engine   │
                                  │ (Ollama)    │
                                  └─────────────┘
```

## 🧠 AI Integration Points

1. **Request Analysis**: AI analyzes incoming requests for patterns
2. **Payload Generation**: Dynamic payload creation based on context
3. **Response Analysis**: Intelligent response pattern recognition
4. **Vulnerability Assessment**: AI-assisted vulnerability classification
5. **Exploit Suggestion**: Automated exploit generation
6. **Report Enhancement**: AI-generated vulnerability explanations

## 🔌 Plugin Architecture

Plugins extend Vulnora's functionality through a well-defined API:

```go
type Plugin interface {
    Initialize(config Config) error
    Execute(context Context) (Result, error)
    Cleanup() error
    GetInfo() PluginInfo
}
```

## 🛡️ Security Considerations

- **TLS Everywhere**: All inter-component communication encrypted
- **Plugin Sandboxing**: Plugins run in isolated environments
- **Input Validation**: All inputs validated and sanitized
- **Least Privilege**: Components run with minimal required permissions
- **Audit Logging**: Comprehensive security event logging

## 📊 Performance Considerations

- **Connection Pooling**: Efficient HTTP connection management
- **Caching**: Intelligent caching of scan results and AI responses
- **Streaming**: Stream processing for large datasets
- **Parallelization**: Concurrent scanning and analysis
- **Resource Limits**: Configurable resource consumption limits
