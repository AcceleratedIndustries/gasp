# GASP - General AI Specialized Process Monitor

**GASP** is a Linux system monitoring tool designed specifically for AI consumption rather than human dashboards. It produces comprehensive, context-rich JSON output that enables AI agents (Claude, ChatGPT, etc.) to diagnose system issues, identify potential problems, and understand system state with minimal queries.

## Project Status

**Current Version:** 0.1.0-dev (MVP in progress)

**Implemented Features:**
- ✅ HTTP server with `/health`, `/metrics`, and `/version` endpoints
- ✅ CPU metrics collection (load averages, utilization, trend analysis)
- ✅ Memory metrics collection (usage, swap, pressure indicators)
- ✅ Rich contextual interpretations for all metrics
- ✅ Concurrent collector architecture
- ✅ Health scoring and concern detection

**Planned Features:**
- Disk I/O and usage metrics
- Network statistics and connection tracking
- Process information and top consumers
- Systemd unit monitoring
- Journal log analysis
- Desktop environment support (Hyprland, KDE, GNOME)
- GPU monitoring (NVIDIA/AMD)
- Baseline tracking and anomaly detection

See `AI-Monitor-Project-Specification.md` for the complete specification.

## Quick Start

### Build from Source

```bash
# Clone the repository
git clone https://github.com/accelerated-industries/gasp
cd gasp

# Build the binary
make build

# Run GASP
./gasp
```

The server will start on `http://localhost:8080` by default.

### Test the API

```bash
# Health check
curl http://localhost:8080/health | jq .

# Version information
curl http://localhost:8080/version | jq .

# Full system metrics
curl http://localhost:8080/metrics | jq .
```

## Example Output

```json
{
  "timestamp": "2025-12-15T17:43:46Z",
  "hostname": "hyperion",
  "uptime": "0m",
  "summary": {
    "health": "healthy",
    "concerns": [],
    "recent_changes": [],
    "score": 100
  },
  "cpu": {
    "load_avg_1m": 0.5,
    "load_avg_5m": 0.41,
    "load_avg_15m": 0.59,
    "cores": 64,
    "utilization_pct": 0.93,
    "baseline_load": 0.5,
    "interpretation": "normal load: load is 0.8% of capacity (0.50 on 64 cores), utilization 0.9%, near baseline",
    "trend": "stable"
  },
  "memory": {
    "total_mb": 257567,
    "used_mb": 12885,
    "available_mb": 244682,
    "usage_percent": 5.0,
    "swap_total_mb": 4095,
    "swap_used_mb": 0,
    "swap_percent": 0,
    "pressure_pct": 0,
    "oom_kills_recent": 0,
    "interpretation": "normal memory usage"
  }
}
```

## Key Design Principles

1. **AI-First Output:** Rich contextual information optimized for LLM consumption
2. **Interpretation Over Raw Data:** Every metric includes human-readable interpretation
3. **Single Source of Truth:** One comprehensive endpoint containing current state and trends
4. **Low Overhead:** Minimal system impact (<1% CPU, <50MB RAM)
5. **Easy Distribution:** Single static binary with no runtime dependencies

## API Endpoints

### GET /health
Returns service health status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-12-15T17:43:46Z",
  "service": "gasp"
}
```

### GET /version
Returns version and build information.

**Response:**
```json
{
  "service": "gasp",
  "version": "0.1.0-dev",
  "build": "development"
}
```

### GET /metrics
Returns comprehensive system snapshot with all collected metrics.

See example output above for structure.

## Development

### Build Commands

```bash
# Development build
make build

# Static binary (no CGO dependencies)
make build-static

# Build for multiple architectures
make build-all

# Run tests
make test

# Format code
make fmt

# Vet code
make vet

# Run locally
make run
```

### Project Structure

```
gasp/
├── cmd/
│   └── gasp/           # Main entry point
├── internal/
│   ├── collectors/     # Metric collectors
│   │   ├── collector.go
│   │   ├── cpu.go
│   │   └── memory.go
│   ├── types/          # Data structures
│   │   └── metrics.go
│   ├── server/         # HTTP server
│   │   └── http.go
│   ├── baseline/       # Baseline tracking (TODO)
│   └── config/         # Configuration (TODO)
├── configs/            # Config files and systemd service
└── scripts/            # Installation scripts
```

### Adding New Collectors

1. Implement the `Collector` interface in `internal/collectors/`
2. Add collection logic reading from `/proc` or `/sys`
3. Include interpretation and trend analysis
4. Register the collector in `cmd/gasp/main.go`

See `internal/collectors/cpu.go` or `memory.go` for examples.

## Configuration

Currently GASP uses command-line flags:

```bash
./gasp --port 8080              # Set HTTP port (default: 8080)
./gasp --config /path/to/config # Load config file (not yet implemented)
./gasp --version                # Show version and exit
```

Configuration file support is planned for Phase 2.

## Architecture

GASP uses a **collector-based architecture** with concurrent metric gathering:

1. Multiple specialized collectors (CPU, Memory, Disk, etc.)
2. Each collector implements a common interface
3. Collectors run concurrently using goroutines
4. Results aggregated into a SystemSnapshot
5. Served via HTTP JSON API

Different metrics are collected at different rates:
- **High-frequency (10s):** CPU, memory, load
- **Medium-frequency (30s):** Processes, network, disk I/O (planned)
- **Low-frequency (5m):** Logs, systemd units (planned)

## Performance Targets

- Binary size: < 15MB
- Memory footprint: < 50MB
- CPU overhead: < 1% (idle), < 5% (during collection)
- HTTP response time: < 100ms
- Collection cycle: < 2 seconds

## Target Platforms

**Primary Support (Phase 1):**
- Arch Linux (workstations)
- Debian/Ubuntu (servers)

**Future Support:**
- Proxmox VE
- Docker/container hosts
- Raspberry Pi / ARM devices

## AI Integration Examples

### Direct Usage
```bash
# AI agent queries via curl
curl -s http://hyperion:8080/metrics | jq .

# Multi-host collection
for host in hyperion proxmox1 proxmox2; do
  curl -s http://${host}:8080/metrics > /tmp/${host}.json
done
```

### Claude Code MCP Server (Planned)
Future integration will expose GASP metrics via MCP tools for seamless Claude Code integration.

## License

To be determined (likely MIT or Apache 2.0)

## Contributing

This is the first Go project at Accelerated Industries. Contributions, suggestions, and feedback are welcome!

See `CLAUDE.md` for detailed development guidance.

## Acknowledgments

- Inspired by Prometheus Node Exporter, Netdata, and Telegraf
- Built for the AI-first monitoring paradigm
- Part of the Accelerated Industries warehouse control system ecosystem
