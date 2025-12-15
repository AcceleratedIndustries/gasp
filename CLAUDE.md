# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ai-monitor** is a Linux system monitoring tool designed specifically for AI consumption rather than human dashboards. It produces comprehensive, context-rich JSON output enabling AI agents to diagnose system issues, identify problems, and understand system state with minimal queries.

**Key Design Principle:** AI-first monitoring with rich contextual information optimized for LLM consumption, not just raw metrics.

**Technology Stack:** Go (for single static binary distribution, excellent /proc parsing, low overhead)

**Organization:** Accelerated Industries - This is the first Go codebase in the organization, aligning with the warehouse control systems ecosystem.

## Project Status

Currently in specification phase. No code has been implemented yet. The full specification is in `AI-Monitor-Project-Specification.md`.

## Architecture & Design

### Core Architecture Pattern

The system uses a **collector-based architecture** with concurrent metric gathering:

```
Collector Interface → Manager → HTTP Server + Optional File Output
     ↓
Multiple specialized collectors run concurrently (goroutines)
     ↓
Aggregated into SystemSnapshot JSON structure
```

### Project Structure (Planned)

```
accelerated-industries/ai-monitor/
├── cmd/
│   └── ai-monitor/
│       └── main.go              # Entry point, CLI flags
├── internal/
│   ├── collectors/
│   │   ├── collector.go         # Interface definition
│   │   ├── cpu.go               # CPU metrics
│   │   ├── memory.go            # Memory metrics
│   │   ├── disk.go              # Disk I/O and usage
│   │   ├── network.go           # Network statistics
│   │   ├── processes.go         # Process information
│   │   ├── systemd.go           # Systemd unit states
│   │   ├── logs.go              # Journal log analysis
│   │   └── desktop.go           # Desktop/Hyprland specific
│   ├── types/
│   │   └── metrics.go           # Data structure definitions
│   ├── baseline/
│   │   └── baseline.go          # Baseline tracking & anomaly detection
│   ├── server/
│   │   └── http.go              # HTTP server & handlers
│   └── config/
│       └── config.go            # Configuration handling
├── configs/
│   ├── ai-monitor.service       # Systemd unit file
│   └── ai-monitor.yaml.example  # Configuration example
└── scripts/
    └── install.sh               # Installation script
```

### Key Architectural Decisions

1. **Collector Interface Pattern:** All metric collectors implement a common interface with `Name()`, `Collect()`, and `Interval()` methods
2. **Concurrent Collection:** Use goroutines to collect metrics in parallel for performance
3. **Variable Collection Rates:**
   - High-frequency (10s): CPU, memory, load
   - Medium-frequency (30s): Processes, network, disk I/O
   - Low-frequency (5m): Logs, systemd units
   - Very low-frequency (15m): Baseline updates, anomaly detection
4. **Interpretation Over Raw Data:** Every metric includes human-readable interpretation and context (e.g., "load is 35% of capacity, normal for this host")
5. **Baseline & Trend Analysis:** System learns normal behavior and detects anomalies using simple statistical methods (2-sigma deviation)

### Data Structure Philosophy

The JSON output is **narrative and contextual**, not just numbers:

```json
{
  "cpu": {
    "load_avg_1m": 2.8,
    "cores": 8,
    "interpretation": "load is 35% of capacity, normal for this host",
    "trend": "increasing",
    "baseline_load": 2.1,
    "top_consumers": [...]
  }
}
```

Every metric category includes:
- Raw values
- Interpretation text
- Trend analysis (increasing/stable/decreasing)
- Baseline comparison
- Top consumers/contributors

## Development Commands

### Building

```bash
# Development build
make build

# Production static binary (no CGO)
make build-static

# Cross-compile for multiple architectures
make build-all

# Install locally with systemd service
make install
```

### Testing

```bash
# Run all tests
make test

# Run specific collector tests
go test ./internal/collectors/...
```

### Code Quality

```bash
# Format code (mandatory before commits)
gofmt -w .

# Lint code
golint ./...

# Vet code
go vet ./...
```

### Running Locally

```bash
# Run binary directly
./ai-monitor

# With custom config
./ai-monitor --config /path/to/config.yaml

# With debug logging
AI_MONITOR_DEBUG=true ./ai-monitor

# Test HTTP endpoints
curl http://localhost:8080/health
curl http://localhost:8080/metrics | jq .
curl http://localhost:8080/version
```

## Implementation Guidelines

### Writing Collectors

1. **Implement the Collector interface** in `internal/collectors/collector.go`
2. **Parse /proc or /sys files directly** - avoid external dependencies when possible
3. **Include interpretation logic** - don't just return raw numbers
4. **Handle errors gracefully** - collectors should not crash the entire system
5. **Use appropriate collection intervals** - respect the interval tier system

Example collector structure:
```go
type CPUCollector struct {
    baseline *baseline.Baseline
}

func (c *CPUCollector) Name() string {
    return "cpu"
}

func (c *CPUCollector) Interval() time.Duration {
    return 10 * time.Second  // High-frequency
}

func (c *CPUCollector) Collect() (interface{}, error) {
    // Parse /proc/loadavg, /proc/stat
    // Calculate deltas and percentages
    // Generate interpretation text
    // Return types.CPUMetrics
}
```

### Data Types

All metric structures are defined in `internal/types/metrics.go`. When adding new metrics:
- Include JSON tags for all fields
- Add interpretation fields as `string`
- Add trend fields as `string` (enum: "increasing", "stable", "decreasing")
- Use appropriate units in field names (e.g., `TotalMB`, `UsagePercent`)

### Configuration

Config file is YAML-based. Support both:
- File-based config: `/etc/ai-monitor/config.yaml`
- Environment variables: `AI_MONITOR_*` prefix

Priority: CLI flags > Environment variables > Config file > Defaults

### Security Considerations

- **Run as unprivileged user** (ai-monitor:ai-monitor)
- **Read-only system access** - no write operations except to /var/lib/ai-monitor
- **No authentication in Phase 1** - designed for trusted networks
- **Systemd hardening** - use NoNewPrivileges, PrivateTmp, ProtectSystem, ProtectHome

## Performance Requirements

**Critical constraints:**
- Binary size: < 15MB
- Memory footprint: < 50MB
- CPU overhead: < 1% idle, < 5% during collection
- HTTP response time: < 100ms
- Collection cycle: < 2 seconds

**Testing performance:**
```bash
# Memory usage
ps aux | grep ai-monitor

# CPU overhead
top -p $(pidof ai-monitor)

# Response time
time curl -s http://localhost:8080/metrics > /dev/null
```

## Target Platforms

**Primary (Phase 1):**
- Arch Linux (workstations with Hyprland/KDE/GNOME)
- Debian/Ubuntu (servers)

**Future:**
- Proxmox VE
- Docker/container hosts
- Raspberry Pi / ARM devices

## Key Libraries (Approved)

- `github.com/shirou/gopsutil` - Cross-platform system metrics
- `github.com/prometheus/procfs` - /proc filesystem parsing
- `github.com/coreos/go-systemd` - Systemd integration

Prefer standard library when possible. Minimize dependencies.

## Desktop Environment Support

The system includes **desktop-specific monitoring** for Linux workstations:

1. **Compositor Detection:** Detect Hyprland, KDE, GNOME via environment variables and processes
2. **Active Window Tracking:** Use compositor-specific IPC (e.g., Hyprland socket)
3. **GPU Monitoring:**
   - NVIDIA: Parse `nvidia-smi` output
   - AMD: Parse `rocm-smi` output
   - Include per-process GPU memory usage

Desktop metrics are optional and only collected when a desktop environment is detected.

## HTTP API Endpoints

```
GET /metrics        # Full system snapshot (primary endpoint)
GET /health         # Service health check
GET /version        # Version and build information
```

Response format: JSON with proper Content-Type headers and CORS support.

## Baseline & Anomaly Detection

The system learns "normal" behavior over a 24-hour learning period:

1. **Baseline Tracking:** Store rolling averages for key metrics
2. **Standard Deviation:** Calculate stddev for each metric
3. **Anomaly Detection:** Flag values > 2 sigma from baseline
4. **Persistence:** Store baselines (decision needed: JSON file vs SQLite)

Baselines update every 15 minutes and inform the interpretation text.

## Build & Deployment

### Makefile Targets

The Makefile should include:
- `build` - Development build
- `build-static` - CGO-disabled static binary
- `build-all` - Cross-compile for linux/amd64 and linux/arm64
- `install` - Install binary, create directories, install systemd service
- `test` - Run all tests
- `clean` - Remove built binaries

### Systemd Service

Service should:
- Run as unprivileged user
- Auto-restart on failure (RestartSec=5s)
- Include security hardening directives
- Depend on network.target

## Common Patterns

### Error Handling in Collectors

```go
func (c *Collector) Collect() (interface{}, error) {
    data, err := c.readSystemFile()
    if err != nil {
        // Log error but return partial data if possible
        log.Printf("collector %s: %v", c.Name(), err)
        return c.fallbackData(), nil
    }
    return c.processData(data), nil
}
```

Collectors should be resilient - prefer returning partial/stale data over failing entirely.

### Concurrent Collection

```go
func (m *Manager) CollectAll() (*types.SystemSnapshot, error) {
    var wg sync.WaitGroup
    results := make(chan CollectorResult, len(m.collectors))

    for _, collector := range m.collectors {
        wg.Add(1)
        go func(c Collector) {
            defer wg.Done()
            data, err := c.Collect()
            results <- CollectorResult{Name: c.Name(), Data: data, Error: err}
        }(collector)
    }

    wg.Wait()
    close(results)

    return m.assembleSnapshot(results), nil
}
```

### Interpretation Generation

Always provide context in interpretation strings:
- Include baseline comparison
- State capacity/limits
- Describe whether values are normal/concerning
- Mention trends

Example: "load is 35% of capacity (2.8 on 8 cores), slightly above baseline of 2.1, increasing trend"

## Open Questions

These architectural decisions need to be made during implementation:

1. **Baseline Storage:** JSON file vs SQLite vs in-memory only
2. **Log Retention:** How much historical data to keep in memory
3. **GPU Support:** Intel GPU monitoring (beyond NVIDIA/AMD)
4. **Authentication Timing:** When to implement API keys (Phase 2 or 3?)
5. **Packaging Priority:** AUR, .deb, .rpm - which first?

## Integration Examples

### Claude Code MCP Server

Future integration will expose ai-monitor via MCP tool:
```typescript
{
  "name": "get_system_metrics",
  "description": "Get comprehensive system metrics from a host",
  "inputSchema": {
    "host": { "type": "string" }
  }
}
```

### Direct AI Usage

```bash
# AI agent queries via curl
curl -s http://hyperion:8080/metrics | jq .

# Multi-host collection
for host in hyperion proxmox1 proxmox2; do
  curl -s http://${host}:8080/metrics > /tmp/${host}.json
done
```

## Code Style

- Follow standard Go conventions (gofmt, golint)
- Document all exported functions and types with godoc comments
- Include unit tests for all collectors
- Use meaningful commit messages (conventional commits preferred)
- Avoid premature optimization - clarity first, then optimize if needed

## Success Criteria

**The implementation is successful when:**
1. An AI agent can diagnose system issues with a single query
2. Installation takes < 5 minutes (binary download + systemd enable)
3. Memory footprint stays < 50MB under normal operation
4. CPU overhead stays < 1% during idle periods
5. Works out-of-box on Arch Linux and Debian with no configuration
