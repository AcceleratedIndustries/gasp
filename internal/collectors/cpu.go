package collectors

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/accelerated-industries/gasp/internal/types"
)

// CPUCollector collects CPU metrics
type CPUCollector struct {
	baseline float64
}

// NewCPUCollector creates a new CPU collector
func NewCPUCollector() *CPUCollector {
	return &CPUCollector{
		baseline: 0.0, // Will be updated over time
	}
}

// Name returns the collector name
func (c *CPUCollector) Name() string {
	return "cpu"
}

// Interval returns how often this collector should run
func (c *CPUCollector) Interval() time.Duration {
	return 10 * time.Second
}

// Collect gathers CPU metrics
func (c *CPUCollector) Collect() (interface{}, error) {
	// Read load averages from /proc/loadavg
	loadavg, err := c.readLoadAvg()
	if err != nil {
		return types.CPUMetrics{}, fmt.Errorf("reading loadavg: %w", err)
	}

	cores := runtime.NumCPU()

	// Read CPU utilization from /proc/stat
	utilization, err := c.readCPUUtilization()
	if err != nil {
		// If we can't read utilization, estimate from load
		utilization = (loadavg[0] / float64(cores)) * 100
	}

	// Initialize baseline if not set
	if c.baseline == 0.0 {
		c.baseline = loadavg[0]
	}

	// Determine trend
	trend := c.determineTrend(loadavg)

	// Generate interpretation
	interpretation := c.generateInterpretation(loadavg[0], float64(cores), utilization)

	metrics := types.CPUMetrics{
		LoadAvg1:       loadavg[0],
		LoadAvg5:       loadavg[1],
		LoadAvg15:      loadavg[2],
		Cores:          cores,
		Utilization:    utilization,
		Baseline:       c.baseline,
		Interpretation: interpretation,
		Trend:          trend,
		TopProcesses:   make([]types.ProcessInfo, 0), // TODO: Implement process tracking
	}

	return metrics, nil
}

// readLoadAvg reads load averages from /proc/loadavg
func (c *CPUCollector) readLoadAvg() ([3]float64, error) {
	var loadavg [3]float64

	file, err := os.Open("/proc/loadavg")
	if err != nil {
		return loadavg, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return loadavg, fmt.Errorf("empty /proc/loadavg")
	}

	fields := strings.Fields(scanner.Text())
	if len(fields) < 3 {
		return loadavg, fmt.Errorf("invalid /proc/loadavg format")
	}

	for i := 0; i < 3; i++ {
		val, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return loadavg, fmt.Errorf("parsing load value: %w", err)
		}
		loadavg[i] = val
	}

	return loadavg, nil
}

// readCPUUtilization calculates CPU utilization percentage
func (c *CPUCollector) readCPUUtilization() (float64, error) {
	// Read /proc/stat twice with a small delay to calculate utilization
	stat1, err := c.readProcStat()
	if err != nil {
		return 0, err
	}

	time.Sleep(100 * time.Millisecond)

	stat2, err := c.readProcStat()
	if err != nil {
		return 0, err
	}

	// Calculate total and idle time differences
	totalDiff := stat2.total - stat1.total
	idleDiff := stat2.idle - stat1.idle

	if totalDiff == 0 {
		return 0, nil
	}

	// Calculate utilization percentage
	utilization := 100.0 * (1.0 - float64(idleDiff)/float64(totalDiff))
	return utilization, nil
}

// cpuStat holds parsed /proc/stat values
type cpuStat struct {
	total uint64
	idle  uint64
}

// readProcStat reads CPU statistics from /proc/stat
func (c *CPUCollector) readProcStat() (cpuStat, error) {
	var stat cpuStat

	file, err := os.Open("/proc/stat")
	if err != nil {
		return stat, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return stat, fmt.Errorf("empty /proc/stat")
	}

	line := scanner.Text()
	if !strings.HasPrefix(line, "cpu ") {
		return stat, fmt.Errorf("invalid /proc/stat format")
	}

	fields := strings.Fields(line)
	if len(fields) < 5 {
		return stat, fmt.Errorf("insufficient fields in /proc/stat")
	}

	// Fields: user nice system idle iowait irq softirq...
	var values []uint64
	for i := 1; i < len(fields) && i <= 10; i++ {
		val, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			continue
		}
		values = append(values, val)
	}

	if len(values) < 4 {
		return stat, fmt.Errorf("failed to parse /proc/stat values")
	}

	// Calculate total (sum of all fields)
	for _, val := range values {
		stat.total += val
	}

	// Idle is the 4th field (index 3)
	stat.idle = values[3]

	return stat, nil
}

// determineTrend analyzes load average trend
func (c *CPUCollector) determineTrend(loadavg [3]float64) string {
	// Compare 1m, 5m, and 15m averages
	if loadavg[0] > loadavg[1]*1.1 && loadavg[1] > loadavg[2]*1.05 {
		return "increasing"
	} else if loadavg[0] < loadavg[1]*0.9 && loadavg[1] < loadavg[2]*0.95 {
		return "decreasing"
	}
	return "stable"
}

// generateInterpretation creates human-readable interpretation of CPU metrics
func (c *CPUCollector) generateInterpretation(load1m float64, cores float64, utilization float64) string {
	loadPerCore := load1m / cores
	capacityPct := loadPerCore * 100

	var status string
	if capacityPct > 100 {
		status = "overloaded"
	} else if capacityPct > 80 {
		status = "high load"
	} else if capacityPct > 50 {
		status = "moderate load"
	} else {
		status = "normal load"
	}

	baselineStr := ""
	if c.baseline > 0 {
		diff := load1m - c.baseline
		if diff > 0.5 {
			baselineStr = fmt.Sprintf(", %.1f above baseline", diff)
		} else if diff < -0.5 {
			baselineStr = fmt.Sprintf(", %.1f below baseline", -diff)
		} else {
			baselineStr = ", near baseline"
		}
	}

	return fmt.Sprintf("%s: load is %.1f%% of capacity (%.2f on %d cores), utilization %.1f%%%s",
		status, capacityPct, load1m, int(cores), utilization, baselineStr)
}
