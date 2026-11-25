package types

import "time"

// SystemSnapshot represents a complete snapshot of system state
type SystemSnapshot struct {
	Timestamp time.Time       `json:"timestamp"`
	Hostname  string          `json:"hostname"`
	Uptime    string          `json:"uptime"`
	Summary   Summary         `json:"summary"`
	CPU       CPUMetrics      `json:"cpu"`
	Memory    MemoryMetrics   `json:"memory"`
	Disk      []DiskMetrics   `json:"disk,omitempty"`
	Network   *NetworkMetrics `json:"network,omitempty"`
	Processes *ProcessSummary `json:"processes,omitempty"`
	Systemd   *SystemdMetrics `json:"systemd,omitempty"`
	Logs      *LogSummary     `json:"logs,omitempty"`
	Desktop   *DesktopMetrics `json:"desktop,omitempty"`
	Packages  *PackageMetrics `json:"packages,omitempty"`
}

// Summary provides high-level health information
type Summary struct {
	Health        string   `json:"health"` // healthy, degraded, critical
	Concerns      []string `json:"concerns"`
	RecentChanges []string `json:"recent_changes"`
	Score         int      `json:"score"` // 0-100 health score
}

// CPUMetrics contains CPU-related metrics and interpretation
type CPUMetrics struct {
	LoadAvg1       float64       `json:"load_avg_1m"`
	LoadAvg5       float64       `json:"load_avg_5m"`
	LoadAvg15      float64       `json:"load_avg_15m"`
	Cores          int           `json:"cores"`
	Utilization    float64       `json:"utilization_pct"`
	Baseline       float64       `json:"baseline_load"`
	Interpretation string        `json:"interpretation"`
	Trend          string        `json:"trend"` // increasing, stable, decreasing
	TopProcesses   []ProcessInfo `json:"top_processes,omitempty"`
}

// MemoryMetrics contains memory-related metrics and interpretation
type MemoryMetrics struct {
	TotalMB        int64         `json:"total_mb"`
	UsedMB         int64         `json:"used_mb"`
	AvailableMB    int64         `json:"available_mb"`
	UsagePercent   float64       `json:"usage_percent"`
	SwapTotalMB    int64         `json:"swap_total_mb"`
	SwapUsedMB     int64         `json:"swap_used_mb"`
	SwapPercent    float64       `json:"swap_percent"`
	PressurePct    float64       `json:"pressure_pct"` // PSI metric if available
	OOMKillsRecent int           `json:"oom_kills_recent"`
	Interpretation string        `json:"interpretation"`
	TopProcesses   []ProcessInfo `json:"top_processes,omitempty"`
}

// ProcessInfo represents information about a single process
type ProcessInfo struct {
	PID        int     `json:"pid"`
	Name       string  `json:"name"`
	CPUPercent float64 `json:"cpu_percent"`
	MemoryMB   int64   `json:"memory_mb"`
	State      string  `json:"state"`
	Uptime     int64   `json:"uptime_seconds"`
}

// DiskMetrics contains disk I/O and usage metrics
type DiskMetrics struct {
	Device         string  `json:"device"`
	MountPoint     string  `json:"mount_point"`
	Filesystem     string  `json:"filesystem"`
	TotalGB        int64   `json:"total_gb"`
	UsedGB         int64   `json:"used_gb"`
	AvailableGB    int64   `json:"available_gb"`
	UsagePercent   float64 `json:"usage_percent"`
	InodesPercent  float64 `json:"inodes_percent"`
	ReadIOPS       int64   `json:"read_iops"`
	WriteIOPS      int64   `json:"write_iops"`
	IOWaitMs       float64 `json:"io_wait_ms"`
	Interpretation string  `json:"interpretation"`
}

// NetworkMetrics contains network statistics
type NetworkMetrics struct {
	Interfaces     []NetworkInterface `json:"interfaces"`
	Connections    ConnectionStats    `json:"connections"`
	ListeningPorts []ListeningPort    `json:"listening_ports,omitempty"`
}

// NetworkInterface represents a single network interface
type NetworkInterface struct {
	Name            string `json:"name"`
	RxBytesPerSec   int64  `json:"rx_bytes_per_sec"`
	TxBytesPerSec   int64  `json:"tx_bytes_per_sec"`
	RxPacketsPerSec int64  `json:"rx_packets_per_sec"`
	TxPacketsPerSec int64  `json:"tx_packets_per_sec"`
	Errors          int64  `json:"errors"`
	Drops           int64  `json:"drops"`
}

// ConnectionStats represents network connection state counts
type ConnectionStats struct {
	Established int `json:"established"`
	TimeWait    int `json:"time_wait"`
	Listening   int `json:"listening"`
}

// ListeningPort represents a port that's listening
type ListeningPort struct {
	Port    int    `json:"port"`
	Process string `json:"process"`
	PID     int    `json:"pid"`
}

// ProcessSummary contains aggregate process information
type ProcessSummary struct {
	Total         int           `json:"total"`
	Running       int           `json:"running"`
	Sleeping      int           `json:"sleeping"`
	Stopped       int           `json:"stopped"`
	Zombie        int           `json:"zombie"`
	Threads       int           `json:"threads"`
	NewSinceLast  []ProcessInfo `json:"new_since_last,omitempty"`
	Interpretation string       `json:"interpretation,omitempty"`
}

// SystemdMetrics contains systemd unit information
type SystemdMetrics struct {
	UnitsTotal     int              `json:"units_total"`
	UnitsActive    int              `json:"units_active"`
	UnitsFailed    int              `json:"units_failed"`
	UnitsInactive  int              `json:"units_inactive"`
	FailedUnits    []string         `json:"failed_units,omitempty"`
	RecentRestarts []SystemdRestart `json:"recent_restarts,omitempty"`
	Interpretation string           `json:"interpretation,omitempty"`
}

// SystemdRestart represents a recent service restart
type SystemdRestart struct {
	Unit      string    `json:"unit"`
	Timestamp time.Time `json:"timestamp"`
	Reason    string    `json:"reason"`
}

// LogSummary contains journal log analysis
type LogSummary struct {
	ErrorsLastInterval   int        `json:"errors_last_interval"`
	WarningsLastInterval int        `json:"warnings_last_interval"`
	MessageRatePerMin    int        `json:"message_rate_per_min"`
	RecentErrors         []LogEntry `json:"recent_errors,omitempty"`
	Interpretation       string     `json:"interpretation"`
}

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Unit      string    `json:"unit"`
	Message   string    `json:"message"`
}

// DesktopMetrics contains desktop environment specific metrics
type DesktopMetrics struct {
	Compositor    string       `json:"compositor"`
	ActiveWindow  string       `json:"active_window"`
	Workspaces    int          `json:"workspaces"`
	SessionUptime string       `json:"session_uptime"`
	GPU           *GPUMetrics  `json:"gpu,omitempty"`
}

// GPUMetrics contains GPU information
type GPUMetrics struct {
	Vendor         string        `json:"vendor"`
	Model          string        `json:"model"`
	UtilizationPct float64       `json:"utilization_pct"`
	MemoryUsedMB   int64         `json:"memory_used_mb"`
	MemoryTotalMB  int64         `json:"memory_total_mb"`
	TemperatureC   int           `json:"temperature_c"`
	PowerWatts     int           `json:"power_watts"`
	Processes      []ProcessInfo `json:"processes,omitempty"`
}

// PackageMetrics reports how up to date the node is, from its own package
// manager. Pointer fields are nil when the value is unknown; unknown is never
// reported as zero or false.
type PackageMetrics struct {
	Manager                string          `json:"manager"` // apt, pacman, unknown
	Method                 string          `json:"method,omitempty"`
	State                  string          `json:"state"`  // up_to_date, updates_pending, security_updates_pending, reboot_required, overdue, unknown
	Status                 string          `json:"status"` // ok, pending, stale, error, unsupported
	NeedsUpdate            bool            `json:"needs_update"`
	NeedsUpdateReasons     []string        `json:"needs_update_reasons,omitempty"`
	UpdatesPending         *int            `json:"updates_pending"`
	SecurityUpdatesPending *int            `json:"security_updates_pending"`
	VulnerableUnfixed      *int            `json:"vulnerable_unfixed,omitempty"`
	SecurityMaxSeverity    string          `json:"security_max_severity,omitempty"`
	SecurityUpdates        []PackageUpdate `json:"security_updates,omitempty"`
	RebootRequired         *bool           `json:"reboot_required"`
	RebootReasons          []string        `json:"reboot_reasons,omitempty"`
	RunningKernel          string          `json:"running_kernel,omitempty"`
	MetadataAgeHours       *float64        `json:"metadata_age_hours"`
	LastUpgrade            *time.Time      `json:"last_upgrade,omitempty"`
	DaysSinceUpgrade       *int            `json:"days_since_upgrade,omitempty"`
	OldestPendingDays      *int            `json:"oldest_pending_days,omitempty"`
	UpdateInProgress       bool            `json:"update_in_progress"`
	LastChecked            *time.Time      `json:"last_checked,omitempty"`
	LastNetworkCheck       *time.Time      `json:"last_network_check,omitempty"`
	CheckDurationMs        int64           `json:"check_duration_ms"`
	Error                  string          `json:"error,omitempty"`
	Interpretation         string          `json:"interpretation"`

	// ScorePenalty is how many health-score points the summary should take
	// off for this node's flags. It is computed from configuration and is
	// not part of the JSON output.
	ScorePenalty int `json:"-"`
}

// PackageUpdate names one package with a known security issue. Routine
// updates are never listed by name.
type PackageUpdate struct {
	Name      string   `json:"name"`
	Installed string   `json:"installed,omitempty"`
	Available string   `json:"available,omitempty"` // empty when no fix is released yet
	Severity  string   `json:"severity,omitempty"`  // arch-audit: critical, high, medium, low
	Issues    []string `json:"issues,omitempty"`    // arch-audit: CVE / AVG ids
}
