# Vulnora - Next-Gen AI-Powered Security Testing Platform

🔍 **Vulnora** is a production-grade, AI-integrated security testing platform written in Go, designed as a next-generation alternative to Burp Suite with intelligent automation and agent-based architecture.

## 🎯 Features

- **AI-Powered Vulnerability Detection**: Local LLM integration for intelligent payload generation and vulnerability analysis
- **Agent-Based Architecture**: Distributed scanning with centralized management
- **Modern GUI**: Cross-platform desktop interface built with Fyne
- **Extensible Plugin System**: Custom modules and extensions
- **Advanced Proxy**: Request/response interception with AI analysis
- **Automated Testing**: Smart fuzzing, brute-force, and exploitation modules
- **Comprehensive Reporting**: PDF/HTML export with AI-generated insights

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   GUI Client    │    │  Agent Manager  │    │   AI Engine     │
│     (Fyne)      │◄──►│    (gRPC)       │◄──►│   (Ollama)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Proxy Module   │    │ Scanner Agents  │    │ Plugin System   │
│ (Interceptor)   │    │  (Distributed)  │    │   (Extensions)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌─────────────────┐
                    │   Data Layer    │
                    │ (SQLite/BoltDB) │
                    └─────────────────┘
```

## 🚀 Quick Start

```bash
# Clone and build
git clone https://github.com/yourusername/vulnora
cd vulnora
go mod tidy
go run cmd/main.go

# Or use the CLI mode
./vulnora cli --target https://example.com
```

## 📁 Project Structure

See `docs/ARCHITECTURE.md` for detailed architecture documentation.

## 🔧 Development

- **Language**: Go 1.21+
- **GUI**: Fyne v2.4+
- **AI**: Ollama integration
- **Communication**: gRPC + TLS
- **Storage**: SQLite + BoltDB
- **Build**: Magefile

## 📜 License

MIT License - see LICENSE file for details.
