# GASP - General AI Specialized Process Monitor

**GASP** is a Linux system monitoring tool designed specifically for AI consumption rather than human dashboards. It produces comprehensive, context-rich JSON output that enables AI agents (Claude, ChatGPT, etc.) to diagnose system issues, identify potential problems, and understand system state with minimal queries.

## Project Status

**Current Version:** 0.1.0-dev (MVP in progress)

> ⚠️ **SECURITY WARNING**: This version of GASP has **NO AUTHENTICATION**. It must run on trusted networks behind a firewall. **DO NOT EXPOSE THIS VERSION TO THE INTERNET.** Authentication will be added in an upcoming release.

**Implemented Features:**
- ✅ HTTP server with `/health`, `/metrics`, and `/version` endpoints
- ✅ CPU metrics collection (load averages, utilization, trend analysis)
- ✅ Memory metrics collection (usage, swap, pressure indicators)
- ✅ Package update status for apt and pacman (pending and security updates, reboot needed, how long since the last upgrade)
- ✅ Rich contextual interpretations for all metrics
- ✅ Concurrent collector architecture
- ✅ Health scoring and concern detection
- ✅ **Claude Code skill bundled** - instant AI diagnostics for your infrastructure

**Planned Features:**
- 🔒 **Next up:** Authentication and authorization (API tokens, secure access)
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

> 💡 **Tip:** After starting GASP, install the bundled Claude Code skill to enable instant AI diagnostics: `claude-code skill install ./skill/gasp-diagnostics.skill`

> ⚠️ **Remember:** This version has no authentication. Run only on trusted networks behind a firewall.

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

### Package update status

The `packages` block in `/metrics` says whether the node is up to date from its package manager's point of view. It supports apt (Debian, Ubuntu) and pacman (Arch and derivatives), runs unprivileged, and never changes package state: it does not run `apt-get update` or `pacman -Sy`.

A node is flagged (`needs_update: true`, one entry in `summary.concerns` per reason) only for:

- a pending security update (apt: an update from a `-security` suite; Arch: `arch-audit`, when installed),
- a required reboot (a newer kernel installed than the one running, or `/run/reboot-required`),
- age: updates pending and no upgrade for `overdue_after` (default 7 days on pacman, 30 days elsewhere), or a pending update waiting that long.

Routine updates are counted but never flag a node. On pacman, updates held back by `IgnorePkg`/`IgnoreGroup` are counted apart (`updates_ignored`), not as pending; a security fix among them is still flagged and listed with `ignored: true`. Unknown values are `null`, never `0`, and missing data never flags. Only packages with a known security issue are named; routine updates appear only as a count.

Checks run in the background, so `/metrics` never waits for them. Local checks re-run when the package database changes, and at least hourly. On Arch, `checkupdates` and `arch-audit` also download fresh package and security data once a day at 03:30 local time (plus up to 30 minutes of random delay), into a private copy under GASP's state directory.

On Arch, install `pacman-contrib` and `fakeroot` (checkupdates needs both) and `arch-audit` for security status. Without checkupdates, GASP falls back to `pacman -Qu` against the system's package lists. If arch-audit's output can't be read (an unrecognized line), GASP keeps the last good result and logs why, rather than reporting no security issues. `make test-arch` runs the live checks against the real tools on an Arch machine.

```yaml
collection:
  packages:
    enabled: true
    refresh_interval: 1h
    network_check_at: "03:30"
    network_jitter: 30m
    allow_network: true         # false: pacman -Qu only, no checkupdates or arch-audit
    stale_after: 168h           # older package lists get a "may be out of date" note
    overdue_after:
      pacman: 168h
      default: 720h
    list_security_updates: true
    max_listed: 20
    score_penalty:              # best guess, to be tuned
      security: 10
      reboot: 5
      overdue: 5
    timeout: 60s
```

### Localhost bypass and reverse proxies

With `auth.localhost_bypass: true`, requests from `127.0.0.1` or `::1` skip authentication. Do not put GASP behind a reverse proxy on the same host with the bypass on: every proxied request arrives from `127.0.0.1`. GASP refuses the bypass for requests carrying `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host` or `X-Real-IP`, but a proxy that adds none of these would still pass every request through unauthenticated. Turn the bypass off when using a proxy. GASP never trusts those headers as the client address.

Direct requests from `127.0.0.1` or `::1` are also never refused as blocked, so an admin on the GASP host can't be locked out of it. Requests carrying the proxy headers above get no such exemption.

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

## AI Integration

### Claude Code Skill (Included!)

GASP includes a **ready-to-use Claude Code skill** that enables instant, intelligent system diagnostics. Once GASP is running on your systems, Claude Code can automatically fetch metrics and provide expert-level analysis of your infrastructure.

#### Installing the Skill

```bash
# From the GASP repository root
claude-code skill install ./skill/gasp-diagnostics.skill
```

Once installed, Claude Code can diagnose any GASP-enabled host on your network:

**Natural language diagnostics:**
- "Check hyperion for me"
- "What's wrong with accelerated.local?"
- "Compare my proxmox nodes"
- "Is the dev server having memory issues?"
- "Why is 192.168.1.100 slow?"

#### What the Skill Does

The `gasp-diagnostics` skill empowers Claude Code to:

1. **Automatically fetch** metrics from any GASP-enabled host via HTTP
2. **Intelligently analyze** system state using metric correlation and baselines
3. **Identify issues** with context-aware pattern recognition (dev workstation vs server vs VM host)
4. **Provide actionable recommendations** specific to the detected problem
5. **Compare multiple hosts** to identify outliers and correlated issues
6. **Understand system context** (desktop environments, container hosts, GPU workloads, etc.)

**Example interaction:**
```
You: Check accelerated.local
Claude: Fetching metrics from accelerated.local...

Issue detected: Memory pressure at 8.2%. The postgres container started
swapping 2 hours ago and is now using 12GB RAM (up from 4GB baseline).
This likely indicates a query leak.

Recommendation: Check recent queries and consider restarting the container.
```

The skill handles network topology automatically - works with mDNS (.local), DNS names, and IP addresses on your trusted network.

#### Security Note for the Skill

The skill connects to GASP instances on port 8080 by default. Since this version has no authentication, ensure:
- GASP runs only on trusted internal networks
- Firewall rules prevent external access to port 8080
- You trust all hosts on the network where GASP is deployed

### Direct API Usage

For non-Claude AI agents or custom integrations:

```bash
# Fetch metrics via curl
curl -s http://hyperion:8080/metrics | jq .

# Multi-host collection script
for host in hyperion proxmox1 proxmox2; do
  curl -s http://${host}:8080/metrics > /tmp/${host}.json
done
```

### Future: MCP Server
A Model Context Protocol (MCP) server is planned to provide even deeper integration with AI tools beyond Claude Code.

## Project Roadmap

GASP is under active development. Here's what's planned:

### Phase 1: Security & Authentication (Next Priority)
- **API token authentication** - Secure access control with token generation and validation
- **Token management** - Utilities for creating, revoking, and rotating tokens
- **Skill updates** - Update the bundled Claude Code skill to support authenticated requests
- **TLS/HTTPS support** - Encrypted transport for production deployments
- **Role-based access** - Read-only vs admin tokens for different use cases

### Phase 2: Enhanced Metrics Collection
- **Disk I/O monitoring** - IOPS, throughput, latency per device
- **Network statistics** - Interface traffic, connections, bandwidth utilization
- **Process information** - Top consumers, detailed process trees, resource tracking
- **Systemd integration** - Unit states, failed services, restart tracking
- **Journal log analysis** - Error rate trending, pattern detection, log correlation

### Phase 3: Advanced Analysis
- **Baseline learning** - 24-hour rolling baselines for anomaly detection
- **Trend analysis** - Statistical deviation detection (2-sigma alerts)
- **Predictive alerts** - Warning before resources are exhausted
- **Persistent baselines** - Store learned behavior across restarts
- **Seasonal patterns** - Weekday vs weekend, business hours vs off-hours

### Phase 4: Desktop & GPU Support
- **Desktop environment detection** - Hyprland, KDE, GNOME, Xorg, Wayland
- **Active window tracking** - Context-aware resource attribution
- **GPU monitoring** - NVIDIA (nvidia-smi), AMD (rocm-smi), Intel
- **Per-process GPU usage** - GPU memory and utilization attribution
- **Thermal monitoring** - Temperature tracking and throttling detection

### Phase 5: Distribution & Deployment
- **Packaging** - AUR (Arch), .deb (Debian/Ubuntu), .rpm (RHEL/Fedora)
- **Systemd hardening** - Enhanced security directives and isolation
- **Auto-installation** - One-command deployment scripts
- **Docker image** - Containerized GASP for Docker hosts
- **Configuration management** - YAML config file support, environment variable overrides

### Phase 6: AI Tooling Ecosystem
- **MCP server implementation** - Native Model Context Protocol support
- **Multi-agent coordination** - Skills for fleet-wide diagnostics
- **Historical data API** - Time-series metrics for trend analysis
- **Alert webhooks** - Proactive notifications for critical issues
- **Integration guides** - Documentation for other AI frameworks (LangChain, AutoGPT, etc.)

### Future Considerations
- Web UI for human consumption (low priority - AI-first focus maintained)
- Plugin system for custom collectors
- Remote host monitoring (agent-based deployment)
- Kubernetes/container orchestration integration
- Windows support (significant undertaking)

> **Note:** This roadmap is subject to change based on user feedback and emerging requirements. The priority is to maintain GASP's core philosophy: AI-first monitoring with rich contextual output.

## License

GASP is licensed under the [GNU General Public License v3.0](LICENSE). This ensures that GASP and any derivatives remain free and open source software.

## Contributing

This is the first Go project at Accelerated Industries. Contributions, suggestions, and feedback are welcome!

See `CLAUDE.md` for detailed development guidance.

## Acknowledgments

- Inspired by Prometheus Node Exporter, Netdata, and Telegraf
- Built for the AI-first monitoring paradigm
- Part of the Accelerated Industries warehouse control system ecosystem
