
## Project Specification

**Project Name:** ai-monitor  
**Organization:** Accelerated Industries  
**Version:** 0.1.0 (Initial Specification)  
**Date:** December 12, 2024

---

## Executive Summary

AI-Monitor is a Linux system monitoring tool designed specifically for AI consumption rather than human dashboards. Unlike traditional monitoring systems that optimize for visual displays and alerting, this system produces comprehensive, context-rich JSON output that enables AI agents (Claude, ChatGPT, etc.) to diagnose system issues, identify potential problems, and understand system state with minimal queries.

The project serves as Accelerated Industries' first Go codebase and aligns with the broader ecosystem of warehouse control systems being built in Go.

---

## Project Goals

### Primary Objectives

1. **AI-First Design:** Provide rich contextual information optimized for LLM consumption
2. **Single Source of Truth:** One comprehensive file/endpoint containing current state and trends
3. **Low Overhead:** Minimal system impact, suitable for workstations and servers
4. **Easy Distribution:** Single static binary with no runtime dependencies
5. **Network Accessible:** HTTP endpoint for remote AI agent access
6. **Self-Documenting:** Metrics include interpretation and context, not just raw numbers

### Success Criteria

- AI agent can diagnose system issues with single query
- Installation requires only binary download + systemd service
- Memory footprint < 50MB
- CPU overhead < 1% on modern systems
- Response time < 100ms for HTTP queries

---

## Architecture Decisions

### Technology Stack: **Go (Confirmed)**

**Rationale:**
- Single static binary distribution
- Excellent standard library for system metrics (`/proc`, `sysfs` parsing)
- Native concurrency for parallel metric collection
- Fast execution and low overhead
- Superior JSON handling
- Industry standard for monitoring tools (Prometheus, Telegraf)
- Aligns with warehouse control system ecosystem

**Alternatives Considered:**
- Python: Poor distribution story, dependency management issues
- Rust: Excellent performance but steeper learning curve, longer compile times

### Deployment Architecture (Confirmed)

```
ai-monitor (single Go binary)
â”œâ”€â”€ HTTP Server: :8080
â”‚   â”œâ”€â”€ GET /metrics        # Full system snapshot (JSON)
â”‚   â”œâ”€â”€ GET /health         # Service health check
â”‚   â””â”€â”€ GET /version        # Version info
â”œâ”€â”€ File Output: /var/lib/ai-monitor/state.json (optional)
â””â”€â”€ Systemd Service: ai-monitor.service
```

### Data Format: **JSON (Confirmed)**

Structured JSON with narrative context rather than raw metrics:

```json
{
  "timestamp": "2024-12-12T10:30:00Z",
  "hostname": "hyperion",
  "summary": {
    "health": "healthy|degraded|critical",
    "concerns": ["array of current issues"],
    "recent_changes": ["narrative of recent events"]
  },
  "cpu": {
    "current_load": 2.8,
    "cores": 8,
    "interpretation": "load is 35% of capacity, normal for this host",
    "trend": "increasing|stable|decreasing",
    "baseline_load": 2.1,
    "top_consumers": [...]
  }
}
```

---

## Core Features (Phase 1 - Confirmed)

### 1. System Metrics Collection

**CPU Monitoring:**
- Current load averages (1m, 5m, 15m)
- Per-core utilization
- Context: number of cores, normal baseline
- Trend analysis (increasing/stable/decreasing)
- Top CPU-consuming processes with deltas

**Memory Monitoring:**
- Usage percentage and absolute values
- Available memory
- Swap usage
- Memory pressure indicators (PSI - Pressure Stall Information)
- OOM kill detection
- Top memory-consuming processes
- Interpretation: "normal usage" vs "memory pressure"

**Disk I/O:**
- Per-device I/O rates
- Queue depths
- I/O wait times
- Disk usage percentages
- Mount points and filesystem types
- Saturation indicators

**Network:**
- Interface statistics (bytes in/out, packets, errors)
- Connection states (established, time-wait, etc.)
- Listening ports with process bindings
- Recent connection rate changes

### 2. Process Intelligence

- Top resource consumers (CPU, memory, I/O)
- Process tree for context
- Zombie/defunct process detection
- Processes in uninterruptible sleep (D state)
- New processes since last snapshot
- Process restart detection

### 3. System Services

- Systemd unit states
- Failed units and recent failures
- Unit restart counts
- Service dependency health
- Recent journal errors/warnings for services

### 4. Desktop Environment Monitoring (Linux Desktop Specific)

**Hyprland/Wayland Support:**
- Active compositor detection
- Active window information
- Workspace count and state
- Desktop session uptime

**GPU Monitoring:**
- NVIDIA GPU utilization (via nvidia-smi)
- AMD GPU metrics (via rocm-smi)
- GPU memory usage
- GPU temperature
- Per-process GPU usage

**Desktop-Specific Processes:**
- Browser resource usage
- IDE/editor resource usage
- Common desktop applications
- Background services (notification daemons, etc.)

### 5. Log Analysis

- Journal errors/warnings from last collection interval
- Parsed common error patterns
- Log message rate (spike detection)
- Specific service failure messages
- Security-relevant events (sudo, auth failures)

### 6. Historical Context & Baselines

- Establish "normal" baseline values per host
- Delta calculations (% change from baseline)
- Micro-trends (last hour, last day)
- Anomaly detection (simple standard deviation based)
- Rolling windows for historical data

### 7. HTTP API

**Endpoints:**
- `GET /metrics` - Full system snapshot (primary endpoint)
- `GET /health` - Service health check (for monitoring the monitor)
- `GET /version` - Version and build information

**Features:**
- No authentication in Phase 1 (localhost/trusted network)
- JSON response format
- CORS headers for browser access
- Configurable listen address and port

---

## Future Possibilities (Not Yet Confirmed)

### Phase 2: Enhanced Collection

**Container Awareness:**
- Docker container metrics
- LXC container state
- Process-to-container mapping
- Container resource limits vs usage

**Proxmox Integration:**
- VM state and resource usage
- Cluster member status
- Storage pool health
- Backup job status
- Migration events

**Security Monitoring:**
- Failed login attempts
- Sudo usage patterns
- Firewall rule hit counts
- SELinux/AppArmor denials
- Open file descriptors by process

**Hardware Health:**
- SMART disk health
- Temperature sensors (lm-sensors)
- Fan speeds
- Power supply status
- RAID array health

### Phase 3: Central Collection

**Multi-Host Aggregation:**
- Central collection service
- Poll multiple ai-monitor instances
- Aggregate view of infrastructure
- Cross-host correlation

**Implementation Options:**
- HTTP scraping (Prometheus-style)
- Push model (agents push to central)
- Message queue integration
- Time-series database storage

### Phase 4: Advanced Features

**Predictive Monitoring:**
- Trend-based predictions
- Resource exhaustion forecasting
- Pattern recognition for recurring issues

**Interactive Querying:**
- Natural language queries to monitoring data
- AI agent can ask follow-up questions
- Historical query support

**Configuration Management:**
- Track configuration file changes
- Diff detection for important files
- Package update history

---

## Technical Design

### Project Structure

```
accelerated-industries/ai-monitor/
â”œâ”€â”€ cmd/
â”‚   â””â”€â”€ ai-monitor/
â”‚       â””â”€â”€ main.go              # Entry point, CLI flags
â”œâ”€â”€ internal/
â”‚   â”œâ”€â”€ collectors/
â”‚   â”‚   â”œâ”€â”€ collector.go         # Interface definition
â”‚   â”‚   â”œâ”€â”€ cpu.go               # CPU metrics
â”‚   â”‚   â”œâ”€â”€ memory.go            # Memory metrics
â”‚   â”‚   â”œâ”€â”€ disk.go              # Disk I/O and usage
â”‚   â”‚   â”œâ”€â”€ network.go           # Network statistics
â”‚   â”‚   â”œâ”€â”€ processes.go         # Process information
â”‚   â”‚   â”œâ”€â”€ systemd.go           # Systemd unit states
â”‚   â”‚   â”œâ”€â”€ logs.go              # Journal log analysis
â”‚   â”‚   â””â”€â”€ desktop.go           # Desktop/Hyprland specific
â”‚   â”œâ”€â”€ types/
â”‚   â”‚   â””â”€â”€ metrics.go           # Data structure definitions
â”‚   â”œâ”€â”€ baseline/
â”‚   â”‚   â””â”€â”€ baseline.go          # Baseline tracking & anomaly detection
â”‚   â”œâ”€â”€ server/
â”‚   â”‚   â””â”€â”€ http.go              # HTTP server & handlers
â”‚   â””â”€â”€ config/
â”‚       â””â”€â”€ config.go            # Configuration handling
â”œâ”€â”€ configs/
â”‚   â”œâ”€â”€ ai-monitor.service       # Systemd unit file
â”‚   â””â”€â”€ ai-monitor.yaml.example  # Configuration example
â”œâ”€â”€ scripts/
â”‚   â””â”€â”€ install.sh               # Installation script
â”œâ”€â”€ go.mod
â”œâ”€â”€ go.sum
â”œâ”€â”€ Makefile
â”œâ”€â”€ README.md
â””â”€â”€ LICENSE
```

### Collector Interface

```go
package collectors

import "ai-monitor/internal/types"

type Collector interface {
    Name() string
    Collect() (interface{}, error)
    Interval() time.Duration  // How often to collect
}

type Manager struct {
    collectors []Collector
}

func (m *Manager) CollectAll() (*types.SystemSnapshot, error) {
    // Concurrent collection using goroutines
}
```

### Data Structures

```go
package types

type SystemSnapshot struct {
    Timestamp     time.Time        `json:"timestamp"`
    Hostname      string           `json:"hostname"`
    Uptime        time.Duration    `json:"uptime"`
    Summary       Summary          `json:"summary"`
    CPU           CPUMetrics       `json:"cpu"`
    Memory        MemoryMetrics    `json:"memory"`
    Disk          []DiskMetrics    `json:"disk"`
    Network       NetworkMetrics   `json:"network"`
    Processes     ProcessSummary   `json:"processes"`
    Systemd       SystemdMetrics   `json:"systemd"`
    Logs          LogSummary       `json:"logs"`
    Desktop       *DesktopMetrics  `json:"desktop,omitempty"`
    Containers    *ContainerMetrics `json:"containers,omitempty"` // Future
}

type Summary struct {
    Health         string    `json:"health"`  // healthy, degraded, critical
    Concerns       []string  `json:"concerns"`
    RecentChanges  []string  `json:"recent_changes"`
    Score          int       `json:"score"`   // 0-100 health score
}

type CPUMetrics struct {
    LoadAvg1       float64        `json:"load_avg_1m"`
    LoadAvg5       float64        `json:"load_avg_5m"`
    LoadAvg15      float64        `json:"load_avg_15m"`
    Cores          int            `json:"cores"`
    Utilization    float64        `json:"utilization_pct"`
    Baseline       float64        `json:"baseline_load"`
    Interpretation string         `json:"interpretation"`
    Trend          string         `json:"trend"` // increasing, stable, decreasing
    TopProcesses   []ProcessInfo  `json:"top_processes"`
}

type MemoryMetrics struct {
    TotalMB        int64   `json:"total_mb"`
    UsedMB         int64   `json:"used_mb"`
    AvailableMB    int64   `json:"available_mb"`
    UsagePercent   float64 `json:"usage_percent"`
    SwapTotalMB    int64   `json:"swap_total_mb"`
    SwapUsedMB     int64   `json:"swap_used_mb"`
    PressurePct    float64 `json:"pressure_pct"` // PSI metric
    OOMKillsRecent int     `json:"oom_kills_recent"`
    Interpretation string  `json:"interpretation"`
    TopProcesses   []ProcessInfo `json:"top_processes"`
}

type ProcessInfo struct {
    PID         int     `json:"pid"`
    Name        string  `json:"name"`
    CPUPercent  float64 `json:"cpu_percent"`
    MemoryMB    int64   `json:"memory_mb"`
    State       string  `json:"state"`
    Uptime      int64   `json:"uptime_seconds"`
}

// Additional types for disk, network, systemd, etc...
```

### Collection Intervals

Different metrics collected at different rates:
- **High-frequency (10s):** CPU, memory, load
- **Medium-frequency (30s):** Processes, network, disk I/O
- **Low-frequency (5m):** Logs, systemd units, configuration
- **Very low-frequency (15m):** Baseline updates, anomaly detection

### Baseline & Anomaly Detection

```go
package baseline

type Baseline struct {
    CPULoadAvg     float64
    MemoryUsagePct float64
    DiskIOPS       map[string]float64
    NetworkBytes   map[string]float64
    
    // Statistical measures
    StdDev         map[string]float64
    LastUpdate     time.Time
}

func (b *Baseline) IsAnomaly(metric string, value float64) bool {
    // Simple sigma-based detection
    baseline := b.Values[metric]
    stddev := b.StdDev[metric]
    return math.Abs(value - baseline) > (2.0 * stddev)
}
```

---

## Implementation Plan

### Phase 1: MVP (Weeks 1-2)

**Week 1:**
- [ ] Project scaffolding and Go module setup
- [ ] Basic HTTP server with /health endpoint
- [ ] CPU metrics collector
- [ ] Memory metrics collector
- [ ] Simple JSON response structure
- [ ] Systemd service file

**Week 2:**
- [ ] Disk metrics collector
- [ ] Network metrics collector
- [ ] Process information collector
- [ ] Top process tracking
- [ ] Basic summary/health status
- [ ] Build and install scripts

**Deliverable:** Working binary that monitors basic system metrics on localhost:8080

### Phase 2: Enhanced Metrics (Weeks 3-4)

**Week 3:**
- [ ] Systemd unit monitoring
- [ ] Journal log analysis
- [ ] Desktop environment detection (Hyprland)
- [ ] GPU metrics (NVIDIA/AMD)
- [ ] Baseline establishment

**Week 4:**
- [ ] Trend analysis (increasing/stable/decreasing)
- [ ] Anomaly detection
- [ ] Recent changes tracking
- [ ] Interpretation text generation
- [ ] Configuration file support

**Deliverable:** Full-featured single-host monitoring with AI-optimized output

### Phase 3: Refinement & Documentation (Week 5)

- [ ] Performance optimization
- [ ] Memory leak testing
- [ ] Comprehensive README
- [ ] API documentation
- [ ] Example AI agent integrations (Claude Code MCP server)
- [ ] Packaging for Arch (AUR) and Debian (.deb)

**Deliverable:** Production-ready release v1.0.0

---

## AI Integration Examples

### Claude Code MCP Server

```typescript
// MCP server exposes system metrics
{
  "name": "get_system_metrics",
  "description": "Get comprehensive system metrics from a host",
  "inputSchema": {
    "type": "object",
    "properties": {
      "host": {
        "type": "string",
        "description": "Hostname or IP address"
      }
    }
  }
}

// Implementation
async function getSystemMetrics(host: string) {
  const response = await fetch(`http://${host}:8080/metrics`);
  return await response.json();
}
```

### Direct AI Usage

```bash
# AI agent (Claude, ChatGPT) can execute:
curl -s http://hyperion:8080/metrics | jq .

# AI can then analyze:
# "I see your load is 8.2 on an 8-core system, which is at 100% capacity.
#  The top processes show 'blender' using 650% CPU (across cores) and
#  'chrome' using 4.2GB RAM. Your memory pressure is at 3.2%, indicating
#  swap is being actively used. This explains the system slowness."
```

### Multi-Host Collection

```bash
# AI agent collects from multiple hosts
for host in hyperion proxmox1 proxmox2 proxmox3; do
  curl -s http://${host}:8080/metrics > /tmp/${host}.json
done

# AI then analyzes all hosts together
# "Looking across your infrastructure, proxmox2 has unusual memory
#  pressure (8.5%) compared to proxmox1 (1.2%) and proxmox3 (0.9%).
#  This correlates with 3 VMs being migrated to proxmox2 in the last hour."
```

---

## Configuration

### Config File Format (YAML)

```yaml
# /etc/ai-monitor/config.yaml

server:
  listen_address: "0.0.0.0:8080"
  enable_cors: true
  
output:
  file_path: "/var/lib/ai-monitor/state.json"
  write_to_file: true
  
collection:
  intervals:
    high_frequency: 10s      # CPU, memory, load
    medium_frequency: 30s    # Processes, network
    low_frequency: 5m        # Logs, systemd
    
baseline:
  enabled: true
  update_interval: 15m
  learning_period: 24h  # How long to establish baseline
  
desktop:
  enabled: true
  monitor_gpu: true
  
collectors:
  enabled:
    - cpu
    - memory
    - disk
    - network
    - processes
    - systemd
    - logs
    - desktop
```

### Environment Variables

```bash
AI_MONITOR_LISTEN=:8080
AI_MONITOR_CONFIG=/etc/ai-monitor/config.yaml
AI_MONITOR_DEBUG=false
```

---

## Build and Deployment

### Build Process

```bash
# Development build
make build

# Production build (static binary)
make build-static

# Cross-compile for different architectures
make build-all

# Install locally
make install
```

### Makefile

```makefile
.PHONY: build build-static install clean test

BINARY_NAME=ai-monitor
VERSION=$(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X main.version=${VERSION}"

build:
	go build ${LDFLAGS} -o ${BINARY_NAME} ./cmd/ai-monitor

build-static:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo ${LDFLAGS} \
		-o ${BINARY_NAME} ./cmd/ai-monitor

build-all:
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}_linux_amd64 ./cmd/ai-monitor
	GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o ${BINARY_NAME}_linux_arm64 ./cmd/ai-monitor

install: build
	sudo install -m 755 ${BINARY_NAME} /usr/local/bin/
	sudo mkdir -p /etc/ai-monitor /var/lib/ai-monitor
	sudo install -m 644 configs/ai-monitor.service /etc/systemd/system/
	sudo systemctl daemon-reload
	@echo "Run: sudo systemctl enable --now ai-monitor"

test:
	go test -v ./...

clean:
	rm -f ${BINARY_NAME} ${BINARY_NAME}_*
```

### Systemd Service

```ini
[Unit]
Description=AI-Optimized System Monitor
After=network.target

[Service]
Type=simple
User=ai-monitor
Group=ai-monitor
ExecStart=/usr/local/bin/ai-monitor
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ai-monitor

[Install]
WantedBy=multi-user.target
```

---

## Target Platforms

### Primary Support (Phase 1)
- Arch Linux (workstations)
- Debian/Ubuntu (servers)
- Desktop environments: Hyprland, KDE Plasma, GNOME

### Future Support (Phase 2+)
- Proxmox VE
- Docker/container hosts
- Raspberry Pi / ARM devices
- Other Linux distributions (Fedora, OpenSUSE, etc.)

---

## Security Considerations

### Phase 1 (Trusted Network)
- No authentication on HTTP endpoint
- Runs as unprivileged user
- Read-only access to system files
- Suitable for home labs, internal networks

### Future Security Features
- API key authentication
- TLS/HTTPS support
- Rate limiting
- IP allowlist/denylist
- Audit logging

---

## Performance Targets

### Resource Usage
- Binary size: < 15MB
- Memory footprint: < 50MB
- CPU overhead: < 1% (idle), < 5% (during collection)
- Disk I/O: Minimal (only for optional file output)

### Response Times
- HTTP /metrics endpoint: < 100ms
- Collection cycle: < 2 seconds
- Baseline update: < 5 seconds

---

## Success Metrics

### Technical Metrics
- Binary successfully builds on Arch and Debian
- All collectors gather accurate data
- HTTP endpoint responds consistently
- No memory leaks over 24-hour run
- CPU overhead stays under targets

### User Experience Metrics
- AI agent successfully diagnoses issues with single query
- Installation takes < 5 minutes
- No configuration required for basic usage
- Works out-of-box on target platforms

### Adoption Metrics
- Used on all Accelerated Industries development machines
- Integrated with Claude Code workflow
- Community interest (GitHub stars, AUR votes)

---

## Comparison to Existing Tools

### vs. Prometheus Node Exporter
- **Node Exporter:** Optimized for time-series scraping, many small metrics
- **ai-monitor:** Optimized for AI consumption, rich context in single query
- **Difference:** ai-monitor provides interpretation and narrative, not just numbers

### vs. Netdata
- **Netdata:** Real-time dashboard with thousands of metrics
- **ai-monitor:** Curated set of metrics with AI-friendly context
- **Difference:** ai-monitor prioritizes depth of context over breadth of metrics

### vs. Traditional Monitoring (Nagios, Zabbix)
- **Traditional:** Threshold-based alerting, human dashboards
- **ai-monitor:** Context-rich output for AI reasoning and diagnosis
- **Difference:** Designed for AI agents to understand system state, not alert humans

---

## Open Questions / Decisions Needed

1. **Baseline Storage:** Where to persist baseline data?
   - Options: JSON file, SQLite database, in-memory only
   
2. **Log Retention:** How much historical data to keep?
   - Consider: Memory constraints, usefulness for trend analysis
   
3. **GPU Monitoring:** Support for Intel GPUs?
   - Current: NVIDIA and AMD planned
   
4. **Authentication:** When to implement API authentication?
   - Phase 2 or 3?
   
5. **Packaging:** Which package formats to prioritize?
   - AUR (Arch), .deb (Debian), .rpm (Fedora), all of the above?

---

## Resources and References

### Go Monitoring Libraries
- github.com/shirou/gopsutil - Cross-platform system metrics
- github.com/prometheus/procfs - /proc filesystem parsing
- github.com/coreos/go-systemd - Systemd integration

### Similar Projects (for reference)
- Prometheus Node Exporter: https://github.com/prometheus/node_exporter
- Netdata: https://github.com/netdata/netdata
- Telegraf: https://github.com/influxdata/telegraf

### Standards
- Prometheus Exposition Format (for comparison)
- OpenMetrics (for future compatibility)
- Systemd Journal Format

---

## Contributing

### Code Style
- Follow standard Go conventions (gofmt, golint)
- Document all exported functions and types
- Include unit tests for collectors
- Use meaningful commit messages

### Development Setup
```bash
git clone https://github.com/accelerated-industries/ai-monitor
cd ai-monitor
go mod download
make build
./ai-monitor --help
```

---

## License

To be determined (likely MIT or Apache 2.0)

---

## Appendix A: Example Output

### Full /metrics Endpoint Response

```json
{
  "timestamp": "2024-12-12T15:30:45Z",
  "hostname": "hyperion",
  "uptime": "15d 6h 23m",
  "summary": {
    "health": "healthy",
    "concerns": [],
    "recent_changes": [
      "Docker container 'postgres' restarted 2h ago",
      "System package update completed 6h ago"
    ],
    "score": 92
  },
  "cpu": {
    "load_avg_1m": 3.2,
    "load_avg_5m": 2.8,
    "load_avg_15m": 2.4,
    "cores": 16,
    "utilization_pct": 22.5,
    "baseline_load": 2.1,
    "interpretation": "load is 20% of capacity, slightly above baseline",
    "trend": "stable",
    "top_processes": [
      {
        "pid": 12345,
        "name": "firefox",
        "cpu_percent": 8.2,
        "memory_mb": 2048,
        "state": "running",
        "uptime_seconds": 45320
      },
      {
        "pid": 23456,
        "name": "code",
        "cpu_percent": 3.1,
        "memory_mb": 1024,
        "state": "running",
        "uptime_seconds": 12400
      }
    ]
  },
  "memory": {
    "total_mb": 32768,
    "used_mb": 24576,
    "available_mb": 8192,
    "usage_percent": 75.0,
    "swap_total_mb": 8192,
    "swap_used_mb": 256,
    "pressure_pct": 0.3,
    "oom_kills_recent": 0,
    "interpretation": "normal usage for this workstation, no memory pressure",
    "top_processes": [
      {
        "pid": 12345,
        "name": "firefox",
        "cpu_percent": 2.1,
        "memory_mb": 4096,
        "state": "running"
      }
    ]
  },
  "disk": [
    {
      "device": "nvme0n1",
      "mount_point": "/",
      "filesystem": "ext4",
      "total_gb": 512,
      "used_gb": 380,
      "available_gb": 132,
      "usage_percent": 74.2,
      "inodes_percent": 12.5,
      "read_iops": 45,
      "write_iops": 120,
      "io_wait_ms": 2.3,
      "interpretation": "normal I/O activity, plenty of space available"
    }
  ],
  "network": {
    "interfaces": [
      {
        "name": "eth0",
        "rx_bytes_per_sec": 1250000,
        "tx_bytes_per_sec": 425000,
        "rx_packets_per_sec": 850,
        "tx_packets_per_sec": 620,
        "errors": 0,
        "drops": 0
      }
    ],
    "connections": {
      "established": 42,
      "time_wait": 8,
      "listening": 15
    },
    "listening_ports": [
      {
        "port": 8080,
        "process": "ai-monitor",
        "pid": 1234
      },
      {
        "port": 22,
        "process": "sshd",
        "pid": 856
      }
    ]
  },
  "processes": {
    "total": 324,
    "running": 2,
    "sleeping": 318,
    "stopped": 0,
    "zombie": 0,
    "threads": 1842,
    "new_since_last": [
      {
        "pid": 45678,
        "name": "code-helper",
        "started": "2024-12-12T15:28:12Z"
      }
    ]
  },
  "systemd": {
    "units_total": 156,
    "units_active": 142,
    "units_failed": 0,
    "units_inactive": 14,
    "failed_units": [],
    "recent_restarts": [
      {
        "unit": "docker.service",
        "timestamp": "2024-12-12T13:45:22Z",
        "reason": "manual restart"
      }
    ]
  },
  "logs": {
    "errors_last_interval": 3,
    "warnings_last_interval": 12,
    "message_rate_per_min": 45,
    "recent_errors": [
      {
        "timestamp": "2024-12-12T15:25:10Z",
        "unit": "bluetooth.service",
        "message": "Failed to connect to device XX:XX:XX:XX:XX:XX"
      }
    ],
    "interpretation": "normal log activity, bluetooth connection issue noted"
  },
  "desktop": {
    "compositor": "Hyprland",
    "active_window": "firefox - Mozilla Firefox",
    "workspaces": 5,
    "session_uptime": "6h 15m",
    "gpu": {
      "vendor": "NVIDIA",
      "model": "RTX 3090",
      "utilization_pct": 15,
      "memory_used_mb": 2048,
      "memory_total_mb": 24576,
      "temperature_c": 52,
      "power_watts": 85,
      "processes": [
        {
          "pid": 12345,
          "name": "firefox",
          "gpu_memory_mb": 512
        }
      ]
    }
  }
}
```

---

## Appendix B: Installation Quick Start

### Arch Linux
```bash
# Build from source
git clone https://github.com/accelerated-industries/ai-monitor
cd ai-monitor
make install

# Or via AUR (future)
yay -S ai-monitor
sudo systemctl enable --now ai-monitor
```

### Debian/Ubuntu
```bash
# Download binary
wget https://github.com/accelerated-industries/ai-monitor/releases/latest/download/ai-monitor_linux_amd64
sudo install ai-monitor_linux_amd64 /usr/local/bin/ai-monitor

# Install systemd service
sudo wget -O /etc/systemd/system/ai-monitor.service \
  https://raw.githubusercontent.com/accelerated-industries/ai-monitor/main/configs/ai-monitor.service
sudo systemctl daemon-reload
sudo systemctl enable --now ai-monitor
```

### Verify Installation
```bash
curl http://localhost:8080/health
curl http://localhost:8080/metrics | jq .summary
```

---

## Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1.0 | 2024-12-12 | Initial | Project specification created |

---

**End of Specification Document**

