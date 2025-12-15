package collectors

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/accelerated-industries/gasp/internal/types"
)

// Collector is the interface that all metric collectors must implement
type Collector interface {
	Name() string
	Collect() (interface{}, error)
	Interval() time.Duration
}

// Manager orchestrates multiple collectors and aggregates their results
type Manager struct {
	collectors []Collector
	hostname   string
	startTime  time.Time
}

// CollectorResult holds the result from a single collector
type CollectorResult struct {
	Name  string
	Data  interface{}
	Error error
}

// NewManager creates a new collector manager
func NewManager() (*Manager, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	return &Manager{
		collectors: make([]Collector, 0),
		hostname:   hostname,
		startTime:  time.Now(),
	}, nil
}

// Register adds a collector to the manager
func (m *Manager) Register(collector Collector) {
	m.collectors = append(m.collectors, collector)
}

// CollectAll runs all collectors concurrently and assembles a SystemSnapshot
func (m *Manager) CollectAll() (*types.SystemSnapshot, error) {
	var wg sync.WaitGroup
	results := make(chan CollectorResult, len(m.collectors))

	// Run all collectors concurrently
	for _, collector := range m.collectors {
		wg.Add(1)
		go func(c Collector) {
			defer wg.Done()
			data, err := c.Collect()
			results <- CollectorResult{
				Name:  c.Name(),
				Data:  data,
				Error: err,
			}
		}(collector)
	}

	// Wait for all collectors to complete
	wg.Wait()
	close(results)

	// Assemble the snapshot
	return m.assembleSnapshot(results)
}

// assembleSnapshot combines collector results into a SystemSnapshot
func (m *Manager) assembleSnapshot(results chan CollectorResult) (*types.SystemSnapshot, error) {
	snapshot := &types.SystemSnapshot{
		Timestamp: time.Now(),
		Hostname:  m.hostname,
		Uptime:    formatUptime(time.Since(m.startTime)),
		Summary: types.Summary{
			Health:        "healthy",
			Concerns:      make([]string, 0),
			RecentChanges: make([]string, 0),
			Score:         100,
		},
	}

	var errors []error

	// Process each collector result
	for result := range results {
		if result.Error != nil {
			errors = append(errors, fmt.Errorf("%s: %w", result.Name, result.Error))
			continue
		}

		// Type assert and assign to appropriate field
		switch result.Name {
		case "cpu":
			if cpu, ok := result.Data.(types.CPUMetrics); ok {
				snapshot.CPU = cpu
			}
		case "memory":
			if mem, ok := result.Data.(types.MemoryMetrics); ok {
				snapshot.Memory = mem
			}
		case "disk":
			if disk, ok := result.Data.([]types.DiskMetrics); ok {
				snapshot.Disk = disk
			}
		case "network":
			if net, ok := result.Data.(types.NetworkMetrics); ok {
				snapshot.Network = &net
			}
		case "processes":
			if proc, ok := result.Data.(types.ProcessSummary); ok {
				snapshot.Processes = &proc
			}
		case "systemd":
			if sys, ok := result.Data.(types.SystemdMetrics); ok {
				snapshot.Systemd = &sys
			}
		case "logs":
			if logs, ok := result.Data.(types.LogSummary); ok {
				snapshot.Logs = &logs
			}
		case "desktop":
			if desktop, ok := result.Data.(types.DesktopMetrics); ok {
				snapshot.Desktop = &desktop
			}
		}
	}

	// Update summary based on collected metrics
	m.updateSummary(snapshot)

	if len(errors) > 0 {
		return snapshot, fmt.Errorf("collector errors: %v", errors)
	}

	return snapshot, nil
}

// updateSummary analyzes collected metrics and updates the summary
func (m *Manager) updateSummary(snapshot *types.SystemSnapshot) {
	concerns := make([]string, 0)
	score := 100

	// Check CPU
	if snapshot.CPU.Cores > 0 {
		loadPerCore := snapshot.CPU.LoadAvg1 / float64(snapshot.CPU.Cores)
		if loadPerCore > 0.9 {
			concerns = append(concerns, "High CPU load")
			score -= 20
		} else if loadPerCore > 0.7 {
			concerns = append(concerns, "Elevated CPU load")
			score -= 10
		}
	}

	// Check Memory
	if snapshot.Memory.UsagePercent > 90 {
		concerns = append(concerns, "Critical memory usage")
		score -= 30
	} else if snapshot.Memory.UsagePercent > 80 {
		concerns = append(concerns, "High memory usage")
		score -= 15
	}

	if snapshot.Memory.SwapPercent > 50 {
		concerns = append(concerns, "High swap usage")
		score -= 10
	}

	// Determine health status
	health := "healthy"
	if score < 50 {
		health = "critical"
	} else if score < 80 {
		health = "degraded"
	}

	snapshot.Summary.Health = health
	snapshot.Summary.Concerns = concerns
	snapshot.Summary.Score = score
}

// formatUptime converts a duration to a human-readable uptime string
func formatUptime(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
