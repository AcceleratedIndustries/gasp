package collectors

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/accelerated-industries/gasp/internal/types"
)

// MemoryCollector collects memory metrics
type MemoryCollector struct {
	baseline float64
}

// NewMemoryCollector creates a new memory collector
func NewMemoryCollector() *MemoryCollector {
	return &MemoryCollector{
		baseline: 0.0,
	}
}

// Name returns the collector name
func (m *MemoryCollector) Name() string {
	return "memory"
}

// Interval returns how often this collector should run
func (m *MemoryCollector) Interval() time.Duration {
	return 10 * time.Second
}

// Collect gathers memory metrics
func (m *MemoryCollector) Collect() (interface{}, error) {
	meminfo, err := m.readMemInfo()
	if err != nil {
		return types.MemoryMetrics{}, fmt.Errorf("reading meminfo: %w", err)
	}

	// Calculate metrics
	totalMB := meminfo["MemTotal"] / 1024
	availableMB := meminfo["MemAvailable"] / 1024
	usedMB := totalMB - availableMB
	usagePercent := (float64(usedMB) / float64(totalMB)) * 100

	swapTotalMB := meminfo["SwapTotal"] / 1024
	swapFreeMB := meminfo["SwapFree"] / 1024
	swapUsedMB := swapTotalMB - swapFreeMB
	swapPercent := 0.0
	if swapTotalMB > 0 {
		swapPercent = (float64(swapUsedMB) / float64(swapTotalMB)) * 100
	}

	// Try to read PSI (Pressure Stall Information) if available
	pressurePct := m.readMemoryPressure()

	// Read OOM kills
	oomKills := m.readOOMKills()

	// Initialize baseline
	if m.baseline == 0.0 {
		m.baseline = usagePercent
	}

	// Generate interpretation
	interpretation := m.generateInterpretation(usagePercent, swapPercent, pressurePct, oomKills)

	metrics := types.MemoryMetrics{
		TotalMB:        totalMB,
		UsedMB:         usedMB,
		AvailableMB:    availableMB,
		UsagePercent:   usagePercent,
		SwapTotalMB:    swapTotalMB,
		SwapUsedMB:     swapUsedMB,
		SwapPercent:    swapPercent,
		PressurePct:    pressurePct,
		OOMKillsRecent: oomKills,
		Interpretation: interpretation,
		TopProcesses:   make([]types.ProcessInfo, 0), // TODO: Implement process tracking
	}

	return metrics, nil
}

// readMemInfo reads memory information from /proc/meminfo
func (m *MemoryCollector) readMemInfo() (map[string]int64, error) {
	meminfo := make(map[string]int64)

	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// Remove trailing colon from key
		key := strings.TrimSuffix(fields[0], ":")
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}

		meminfo[key] = value
	}

	// Verify we have required fields
	required := []string{"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
	for _, field := range required {
		if _, ok := meminfo[field]; !ok {
			return nil, fmt.Errorf("missing required field: %s", field)
		}
	}

	return meminfo, scanner.Err()
}

// readMemoryPressure reads PSI memory pressure if available
func (m *MemoryCollector) readMemoryPressure() float64 {
	file, err := os.Open("/proc/pressure/memory")
	if err != nil {
		return 0.0 // PSI not available on this system
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "some avg10=") {
			// Parse "some avg10=X.XX avg60=Y.YY avg300=Z.ZZ total=NNNN"
			fields := strings.Fields(line)
			for _, field := range fields {
				if strings.HasPrefix(field, "avg10=") {
					valueStr := strings.TrimPrefix(field, "avg10=")
					if value, err := strconv.ParseFloat(valueStr, 64); err == nil {
						return value
					}
				}
			}
		}
	}

	return 0.0
}

// readOOMKills attempts to count recent OOM kills
func (m *MemoryCollector) readOOMKills() int {
	// Try to read from dmesg or journalctl
	// For now, return 0 as this requires more complex implementation
	// TODO: Implement OOM kill detection via dmesg or journal
	return 0
}

// generateInterpretation creates human-readable interpretation of memory metrics
func (m *MemoryCollector) generateInterpretation(usagePercent, swapPercent, pressurePct float64, oomKills int) string {
	var parts []string

	// Memory usage status
	if usagePercent > 95 {
		parts = append(parts, "critical memory usage")
	} else if usagePercent > 90 {
		parts = append(parts, "very high memory usage")
	} else if usagePercent > 80 {
		parts = append(parts, "high memory usage")
	} else if usagePercent > 60 {
		parts = append(parts, "moderate memory usage")
	} else {
		parts = append(parts, "normal memory usage")
	}

	// Swap usage
	if swapPercent > 50 {
		parts = append(parts, "heavy swap usage indicates memory pressure")
	} else if swapPercent > 20 {
		parts = append(parts, "some swap usage")
	} else if swapPercent > 0 {
		parts = append(parts, "minimal swap usage")
	}

	// PSI pressure
	if pressurePct > 5.0 {
		parts = append(parts, fmt.Sprintf("high memory pressure (%.1f%%)", pressurePct))
	} else if pressurePct > 1.0 {
		parts = append(parts, fmt.Sprintf("some memory pressure (%.1f%%)", pressurePct))
	}

	// OOM kills
	if oomKills > 0 {
		parts = append(parts, fmt.Sprintf("%d recent OOM kills", oomKills))
	}

	// Baseline comparison
	if m.baseline > 0 {
		diff := usagePercent - m.baseline
		if diff > 10 {
			parts = append(parts, fmt.Sprintf("%.1f%% above baseline", diff))
		} else if diff < -10 {
			parts = append(parts, fmt.Sprintf("%.1f%% below baseline", -diff))
		}
	}

	if len(parts) == 0 {
		return "memory healthy"
	}

	return strings.Join(parts, "; ")
}
