package collectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/accelerated-industries/gasp/internal/config"
	"github.com/accelerated-industries/gasp/internal/types"
)

// PackageCollector reports how up to date the node is from the local
// package manager's point of view.
//
// Package checks can take seconds (and on Arch, a daily network check), so
// they never run inside Collect. A background goroutine refreshes a cached
// result and Collect returns a copy of it at once.
type PackageCollector struct {
	settings config.PackageSettings
	fs       pkgFS
	runner   cmdRunner
	stateDir string
	now      func() time.Time
	tick     time.Duration
	rng      *rand.Rand

	backend pkgBackend
	manager string

	startOnce sync.Once
	cancel    context.CancelFunc
	done      chan struct{}

	mu     sync.RWMutex
	cached types.PackageMetrics

	// Everything below is touched only by the refresh goroutine.
	state            pkgState
	lastStamp        string
	lastLocal        time.Time
	lastResult       *checkResult
	lastSuccess      time.Time
	lastErr          string
	lastLoggedErr    string
	everSucceeded    bool
	nextNetwork      time.Time
	networkFailures  int
	networkSupported bool
	lastDuration     time.Duration
	inProgress       bool
}

// pkgState is persisted in the state directory.
type pkgState struct {
	LastNetworkCheck *time.Time           `json:"last_network_check,omitempty"`
	FirstSeen        map[string]time.Time `json:"first_seen"`
	Audit            *auditState          `json:"arch_audit,omitempty"`
}

const (
	packagesStateFile = "packages-state.json"
	packagesTick      = 5 * time.Minute
	// After a failed network check, retry this often, at most
	// maxNetworkRetries times, then wait for the next daily slot.
	networkRetryDelay = time.Hour
	maxNetworkRetries = 3
)

// packageManagerProcs are process names that mean an install or upgrade is
// running. "unattended-upgr" is how unattended-upgrades shows in comm,
// which is cut to 15 characters.
var packageManagerProcs = map[string]bool{
	"apt": true, "apt-get": true, "dpkg": true, "unattended-upgr": true, "pacman": true,
}

// NewPackageCollector returns a collector for the node's package manager.
// stateDir holds what must survive restarts (first-seen times, the last
// network check, checkupdates' private database copy). An empty stateDir
// works but forgets those on restart.
func NewPackageCollector(settings config.PackageSettings, stateDir string) *PackageCollector {
	return newPackageCollector(settings, stateDir, pkgFS{root: "/"}, execRunner{}, time.Now)
}

func newPackageCollector(settings config.PackageSettings, stateDir string, fs pkgFS, runner cmdRunner, now func() time.Time) *PackageCollector {
	c := &PackageCollector{
		settings: settings,
		fs:       fs,
		runner:   runner,
		stateDir: stateDir,
		now:      now,
		tick:     packagesTick,
		rng:      rand.New(rand.NewSource(now().UnixNano())),
		done:     make(chan struct{}),
		state:    pkgState{FirstSeen: map[string]time.Time{}},
	}
	c.backend = c.detect()
	if c.backend == nil {
		c.manager = "unknown"
		c.cached = types.PackageMetrics{
			Manager:        "unknown",
			State:          "unknown",
			Status:         "unsupported",
			Interpretation: "no supported package manager found (checked apt, pacman)",
		}
	} else {
		c.manager = c.backend.Name()
		c.cached = types.PackageMetrics{
			Manager:        c.manager,
			State:          "unknown",
			Status:         "pending",
			Interpretation: "package check has not finished yet",
		}
	}
	return c
}

// detect picks the package manager from /etc/os-release, confirmed by the
// tool being installed, and otherwise by probing for the tools.
func (c *PackageCollector) detect() pkgBackend {
	id, idLike := c.fs.osRelease()
	families := append([]string{id}, idLike...)
	has := func(name string) bool { _, err := c.runner.LookPath(name); return err == nil }
	apt := func() pkgBackend { return &aptBackend{fs: c.fs, runner: c.runner} }
	pacman := func() pkgBackend {
		b := &pacmanBackend{fs: c.fs, runner: c.runner}
		if c.stateDir != "" {
			b.dbDir = filepath.Join(c.stateDir, "checkup-db")
		}
		return b
	}
	for _, f := range families {
		switch f {
		case "debian", "ubuntu":
			if has("apt-get") {
				return apt()
			}
		case "arch":
			if has("pacman") {
				return pacman()
			}
		}
	}
	if has("apt-get") {
		return apt()
	}
	if has("pacman") {
		return pacman()
	}
	return nil
}

// Name returns the collector name.
func (c *PackageCollector) Name() string { return "packages" }

// Interval returns the local refresh ceiling.
func (c *PackageCollector) Interval() time.Duration { return c.settings.RefreshInterval }

// Collect returns the cached result. It never blocks on a package check and
// never returns an error: failures show up as status "stale" or "error" in
// the block itself.
func (c *PackageCollector) Collect() (interface{}, error) {
	c.Start()
	c.mu.RLock()
	defer c.mu.RUnlock()
	return copyPackageMetrics(c.cached), nil
}

// Start launches the background refresh. It is safe to call more than once;
// Collect calls it too.
func (c *PackageCollector) Start() {
	c.startOnce.Do(func() {
		if c.backend == nil {
			close(c.done)
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		c.cancel = cancel
		go c.run(ctx)
	})
}

// Stop ends the background refresh and waits for it.
func (c *PackageCollector) Stop() {
	c.startOnce.Do(func() { close(c.done) })
	if c.cancel != nil {
		c.cancel()
	}
	<-c.done
}

func (c *PackageCollector) run(ctx context.Context) {
	defer close(c.done)
	c.prepare()
	c.safeRefresh(ctx, true)

	ticker := time.NewTicker(c.tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.safeRefresh(ctx, false)
		}
	}
}

// prepare loads the saved state and decides whether and when the network
// check runs. run calls it once before the first refresh.
func (c *PackageCollector) prepare() {
	c.loadState()
	c.networkSupported = c.settings.AllowNetwork && c.backend.Name() == "pacman"
	c.scheduleFirstNetwork()
}

// safeRefresh keeps one bad check from killing the goroutine.
func (c *PackageCollector) safeRefresh(ctx context.Context, force bool) {
	defer func() {
		if r := recover(); r != nil {
			c.recordError(fmt.Sprintf("internal error: %v", r))
			c.publish()
		}
	}()
	c.refresh(ctx, force)
}

// refresh runs a check when one is due and republishes the cache.
func (c *PackageCollector) refresh(ctx context.Context, force bool) {
	now := c.now()
	if busy := c.fs.runningCommands(packageManagerProcs); len(busy) > 0 {
		// Skip the check: the package database may be half written.
		c.inProgress = true
		c.publish()
		return
	}
	c.inProgress = false

	network := c.networkSupported && !now.Before(c.nextNetwork)
	stamp := c.backend.StateStamp()
	localDue := force || stamp != c.lastStamp || now.Sub(c.lastLocal) >= c.settings.RefreshInterval
	if !network && !localDue {
		// Nothing to run, but ages ("3 days ago") still move.
		c.publish()
		return
	}

	checkCtx, cancel := context.WithTimeout(ctx, c.settings.Timeout)
	defer cancel()
	start := c.now()
	var res checkResult
	var err error
	if network {
		res, err = c.backend.NetworkCheck(checkCtx)
		switch {
		case errors.Is(err, errNoNetworkCheck):
			c.networkSupported = false
			res, err = c.backend.LocalCheck(checkCtx)
		case err != nil:
			c.networkFailures++
			c.scheduleNetworkAfterFailure(now)
			// The network may be down; the local databases still answer.
			if lres, lerr := c.backend.LocalCheck(checkCtx); lerr == nil {
				c.recordError("network check failed: " + err.Error())
				res, err = lres, nil
			}
		default:
			c.networkFailures = 0
			t := now
			c.state.LastNetworkCheck = &t
			c.state.Audit = auditOf(c.backend)
			c.scheduleNextNetwork(now)
		}
	} else {
		res, err = c.backend.LocalCheck(checkCtx)
	}
	if ctx.Err() != nil {
		return
	}
	c.lastDuration = c.now().Sub(start)
	c.lastLocal = now
	c.lastStamp = stamp

	if err != nil {
		c.recordError(err.Error())
	} else {
		if !network || c.networkFailures == 0 {
			c.lastErr = ""
		}
		r := res
		c.lastResult = &r
		c.lastSuccess = now
		c.everSucceeded = true
		c.trackFirstSeen(res.Pending, now)
	}
	c.saveState()
	c.publish()
}

func auditOf(b pkgBackend) *auditState {
	if p, ok := b.(*pacmanBackend); ok {
		return p.saveAudit()
	}
	return nil
}

func (c *PackageCollector) recordError(msg string) {
	if len(msg) > 300 {
		msg = msg[:300]
	}
	c.lastErr = msg
	if msg != c.lastLoggedErr {
		log.Printf("packages: %s", msg)
		c.lastLoggedErr = msg
	}
}

// publish evaluates the current facts and replaces the cache.
func (c *PackageCollector) publish() {
	now := c.now()
	f := pkgFacts{
		Manager:       c.manager,
		Error:         c.lastErr,
		Result:        c.lastResult,
		LastSuccess:   c.lastSuccess,
		EverSucceeded: c.everSucceeded,
		Reboot:        detectReboot(c.fs, c.backend.KeepsOldKernels()),
		Duration:      c.lastDuration,
		InProgress:    c.inProgress,
	}
	f.MetadataTime, f.HaveMetadata = c.backend.MetadataTime()
	f.LastUpgrade, f.HaveUpgrade = c.backend.LastUpgrade()
	if c.state.LastNetworkCheck != nil {
		f.LastNetworkCheck = *c.state.LastNetworkCheck
	}
	if c.lastResult != nil {
		f.OldestPending, f.HavePendingAge = c.oldestPending(c.lastResult.Pending, now)
	}
	m := evaluatePackages(f, c.settings, now)
	c.mu.Lock()
	c.cached = m
	c.mu.Unlock()
}

// ---- first-seen tracking and state file ----

func pendingKey(p pendingPackage) string { return p.Name + "@" + p.Available }

// trackFirstSeen records when each pending package/version was first seen
// and forgets the ones no longer pending.
func (c *PackageCollector) trackFirstSeen(pending []pendingPackage, now time.Time) {
	keep := make(map[string]time.Time, len(pending))
	for _, p := range pending {
		k := pendingKey(p)
		if t, ok := c.state.FirstSeen[k]; ok {
			keep[k] = t
		} else {
			keep[k] = now
		}
	}
	c.state.FirstSeen = keep
}

func (c *PackageCollector) oldestPending(pending []pendingPackage, now time.Time) (time.Duration, bool) {
	var oldest time.Duration
	found := false
	for _, p := range pending {
		if t, ok := c.state.FirstSeen[pendingKey(p)]; ok {
			if age := now.Sub(t); !found || age > oldest {
				oldest, found = age, true
			}
		}
	}
	return oldest, found
}

func (c *PackageCollector) loadState() {
	if c.stateDir == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(c.stateDir, packagesStateFile))
	if err != nil {
		return
	}
	var st pkgState
	if err := json.Unmarshal(data, &st); err != nil {
		log.Printf("packages: ignoring unreadable %s: %v", packagesStateFile, err)
		return
	}
	if st.FirstSeen == nil {
		st.FirstSeen = map[string]time.Time{}
	}
	c.state = st
	if p, ok := c.backend.(*pacmanBackend); ok {
		p.restoreAudit(st.Audit)
	}
}

// saveState writes the state file atomically through a unique temp file, so
// two writers can never interleave.
func (c *PackageCollector) saveState() {
	if c.stateDir == "" {
		return
	}
	data, err := json.MarshalIndent(c.state, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(c.stateDir, 0o700); err != nil {
		c.recordError("cannot create state dir: " + err.Error())
		return
	}
	tmp, err := os.CreateTemp(c.stateDir, packagesStateFile+".*.tmp")
	if err != nil {
		c.recordError("cannot write state: " + err.Error())
		return
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(name)
		return
	}
	if err := os.Rename(name, filepath.Join(c.stateDir, packagesStateFile)); err != nil {
		os.Remove(name)
	}
}

// ---- network schedule ----

// scheduleFirstNetwork runs the network check at startup only if the last
// successful one is over 24 hours old; otherwise it waits for the next
// daily slot.
func (c *PackageCollector) scheduleFirstNetwork() {
	now := c.now()
	if c.state.LastNetworkCheck == nil || now.Sub(*c.state.LastNetworkCheck) > 24*time.Hour {
		c.nextNetwork = now
		return
	}
	c.scheduleNextNetwork(now)
}

// scheduleNextNetwork picks the next network_check_at after now, plus a
// random delay of up to network_jitter.
func (c *PackageCollector) scheduleNextNetwork(now time.Time) {
	c.nextNetwork = nextDailySlot(now, c.settings.NetworkCheckHour, c.settings.NetworkCheckMinute, c.jitter())
}

func (c *PackageCollector) scheduleNetworkAfterFailure(now time.Time) {
	if c.networkFailures <= maxNetworkRetries {
		c.nextNetwork = now.Add(networkRetryDelay)
		return
	}
	c.networkFailures = 0
	c.scheduleNextNetwork(now)
}

func (c *PackageCollector) jitter() time.Duration {
	if c.settings.NetworkJitter <= 0 {
		return 0
	}
	return time.Duration(c.rng.Int63n(int64(c.settings.NetworkJitter)))
}

// nextDailySlot returns the first hour:minute (local time of now) plus
// jitter that is strictly after now.
func nextDailySlot(now time.Time, hour, minute int, jitter time.Duration) time.Time {
	slot := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location()).Add(jitter)
	if !slot.After(now) {
		slot = time.Date(now.Year(), now.Month(), now.Day()+1, hour, minute, 0, 0, now.Location()).Add(jitter)
	}
	return slot
}

// ---- roll-up ----

// pkgFacts is everything the roll-up needs. Keeping it separate from the
// collector makes the decision rules easy to test as a table.
type pkgFacts struct {
	Manager          string
	Error            string
	Result           *checkResult
	LastSuccess      time.Time
	EverSucceeded    bool
	Reboot           rebootStatus
	MetadataTime     time.Time
	HaveMetadata     bool
	LastUpgrade      time.Time
	HaveUpgrade      bool
	OldestPending    time.Duration
	HavePendingAge   bool
	LastNetworkCheck time.Time
	Duration         time.Duration
	InProgress       bool
}

var severityRank = map[string]int{"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// evaluatePackages applies the decided rule (design 5.2): a node needs
// updating only for a security update, a required reboot, or age. Routine
// updates are counted but never flag, and missing data never flags.
func evaluatePackages(f pkgFacts, s config.PackageSettings, now time.Time) types.PackageMetrics {
	m := types.PackageMetrics{Manager: f.Manager, State: "unknown", NeedsUpdateReasons: []string{}, UpdateInProgress: f.InProgress}
	if f.Duration > 0 {
		m.CheckDurationMs = f.Duration.Milliseconds()
	}
	if !f.LastNetworkCheck.IsZero() {
		t := f.LastNetworkCheck
		m.LastNetworkCheck = &t
	}
	if f.HaveMetadata {
		h := roundTo(now.Sub(f.MetadataTime).Hours(), 1)
		if h < 0 {
			h = 0
		}
		m.MetadataAgeHours = &h
	}
	if f.HaveUpgrade {
		t := f.LastUpgrade
		m.LastUpgrade = &t
		d := daysBetween(f.LastUpgrade, now)
		m.DaysSinceUpgrade = &d
	}
	if f.Reboot.Known {
		r := f.Reboot.Required
		m.RebootRequired = &r
		m.RebootReasons = f.Reboot.Reasons
	}
	m.RunningKernel = f.Reboot.Running

	switch {
	case f.Result != nil && f.Error != "":
		m.Status = "stale"
	case f.Result != nil:
		m.Status = "ok"
	case f.Error != "":
		m.Status = "error"
	default:
		m.Status = "pending"
	}
	m.Error = f.Error

	overdue := s.OverdueFor(f.Manager)
	var security []types.PackageUpdate
	pending := 0

	if r := f.Result; r != nil {
		m.Method = r.Method
		t := f.LastSuccess
		m.LastChecked = &t
		pending = len(r.Pending)
		m.UpdatesPending = &pending
		if r.IgnoredKnown {
			ig := len(r.Ignored)
			m.UpdatesIgnored = &ig
		}
		if r.SecurityKnown {
			security = r.Security
			n := len(security)
			m.SecurityUpdatesPending = &n
			if r.Unfixed != nil {
				u := len(r.Unfixed)
				m.VulnerableUnfixed = &u
			}
			max := ""
			for _, s := range security {
				if severityRank[s.Severity] > severityRank[max] {
					max = s.Severity
				}
			}
			m.SecurityMaxSeverity = max
			if s.ListSecurityUpdates && n > 0 {
				listed := append([]types.PackageUpdate{}, security...)
				sort.Slice(listed, func(i, j int) bool {
					ri, rj := severityRank[listed[i].Severity], severityRank[listed[j].Severity]
					if ri != rj {
						return ri > rj
					}
					return listed[i].Name < listed[j].Name
				})
				if len(listed) > s.MaxListed {
					listed = listed[:s.MaxListed]
				}
				m.SecurityUpdates = listed
			}
		}
		if f.HavePendingAge && pending > 0 {
			d := int(f.OldestPending / (24 * time.Hour))
			m.OldestPendingDays = &d
		}
	}

	metadataStale := f.HaveMetadata && now.Sub(f.MetadataTime) > s.StaleAfter

	// Triggers.
	penalty := 0
	securityFlag := m.SecurityUpdatesPending != nil && *m.SecurityUpdatesPending > 0
	if securityFlag {
		reason := plural(*m.SecurityUpdatesPending, "security update") + " pending"
		var notes []string
		if m.SecurityMaxSeverity != "" {
			notes = append(notes, "max severity: "+m.SecurityMaxSeverity)
		}
		if n := countIgnored(security); n > 0 {
			notes = append(notes, fmt.Sprintf("%d held back by IgnorePkg", n))
		}
		if len(notes) > 0 {
			reason += " (" + strings.Join(notes, ", ") + ")"
		}
		m.NeedsUpdateReasons = append(m.NeedsUpdateReasons, reason)
		penalty += s.PenaltySecurity
	}
	rebootFlag := m.RebootRequired != nil && *m.RebootRequired
	if rebootFlag {
		reason := "reboot required"
		if len(f.Reboot.Reasons) > 0 {
			reason = "reboot required: " + strings.Join(f.Reboot.Reasons, "; ")
		}
		m.NeedsUpdateReasons = append(m.NeedsUpdateReasons, reason)
		penalty += s.PenaltyReboot
	}
	// Age. "No upgrade in N days" only counts when there is something to
	// upgrade, or when the package lists are too old to tell.
	overdueFlag := false
	if f.Result != nil && m.DaysSinceUpgrade != nil && now.Sub(f.LastUpgrade) >= overdue && (pending > 0 || metadataStale) {
		m.NeedsUpdateReasons = append(m.NeedsUpdateReasons, fmt.Sprintf("no upgrade in %d days", *m.DaysSinceUpgrade))
		overdueFlag = true
	} else if m.OldestPendingDays != nil && f.OldestPending >= overdue {
		m.NeedsUpdateReasons = append(m.NeedsUpdateReasons, fmt.Sprintf("an update has been waiting %d days", *m.OldestPendingDays))
		overdueFlag = true
	}
	if overdueFlag {
		penalty += s.PenaltyOverdue
	}
	m.NeedsUpdate = len(m.NeedsUpdateReasons) > 0
	m.ScorePenalty = penalty

	switch {
	case f.Result == nil && !rebootFlag:
		m.State = "unknown"
	case securityFlag:
		m.State = "security_updates_pending"
	case rebootFlag:
		m.State = "reboot_required"
	case overdueFlag:
		m.State = "overdue"
	case pending > 0:
		m.State = "updates_pending"
	default:
		m.State = "up_to_date"
	}

	m.Interpretation = interpretPackages(m, f, s, now, metadataStale)
	if len(m.NeedsUpdateReasons) == 0 {
		m.NeedsUpdateReasons = nil
	}
	return m
}

func interpretPackages(m types.PackageMetrics, f pkgFacts, s config.PackageSettings, now time.Time, metadataStale bool) string {
	var parts []string
	if f.Result != nil && f.Error != "" && now.Sub(f.LastSuccess) > 3*s.RefreshInterval {
		parts = append(parts, "last successful check "+ago(now.Sub(f.LastSuccess)))
	}
	if f.Result == nil {
		switch m.Status {
		case "error":
			parts = append(parts, "package check failed: "+f.Error)
		default:
			parts = append(parts, "package check has not finished yet")
		}
	} else {
		pending := *m.UpdatesPending
		// Security updates among pending packages, and those held back by
		// IgnorePkg, are described separately.
		var secPending, secIgnored []types.PackageUpdate
		for _, u := range m.SecurityUpdates {
			if u.Ignored {
				secIgnored = append(secIgnored, u)
			} else {
				secPending = append(secPending, u)
			}
		}
		secIgnoredN := 0
		if f.Result.SecurityKnown {
			secIgnoredN = countIgnored(f.Result.Security)
		}
		secPendingN := 0
		if m.SecurityUpdatesPending != nil {
			secPendingN = *m.SecurityUpdatesPending - secIgnoredN
		}
		ignoredN := 0
		if m.UpdatesIgnored != nil {
			ignoredN = *m.UpdatesIgnored
		}
		switch {
		case pending == 0 && ignoredN > 0:
			parts = append(parts, "nothing pending outside IgnorePkg")
		case pending == 0:
			parts = append(parts, "up to date per local "+f.Manager+" database")
		case secPendingN > 0:
			parts = append(parts, fmt.Sprintf("%s pending, %d of them security", plural(pending, "update"), secPendingN)+nameList(secPending))
		case m.SecurityUpdatesPending != nil:
			parts = append(parts, plural(pending, "update")+" pending, none of them security")
		default:
			parts = append(parts, plural(pending, "update")+" pending")
		}
		if ignoredN > 0 {
			parts = append(parts, plural(ignoredN, "update")+" held back by IgnorePkg, not counted as pending")
		}
		if secIgnoredN > 0 {
			parts = append(parts, plural(secIgnoredN, "security update")+" held back by IgnorePkg"+nameList(secIgnored))
		}
		if m.SecurityUpdatesPending == nil {
			if f.Manager == "pacman" {
				parts = append(parts, "security status unknown (install arch-audit to check)")
			} else {
				parts = append(parts, "security status unknown")
			}
		}
		if m.VulnerableUnfixed != nil && *m.VulnerableUnfixed > 0 {
			parts = append(parts, plural(*m.VulnerableUnfixed, "vulnerable package")+" with no fix yet")
		}
	}
	if f.HaveMetadata {
		age := now.Sub(f.MetadataTime)
		if metadataStale {
			parts = append(parts, "package lists are "+span(age)+" old, so counts may be out of date")
		} else {
			parts = append(parts, "package lists refreshed "+ago(age))
		}
	}
	if m.DaysSinceUpgrade != nil {
		parts = append(parts, "last upgrade "+daysAgo(*m.DaysSinceUpgrade))
	}
	if m.OldestPendingDays != nil && *m.OldestPendingDays > 0 {
		parts = append(parts, "oldest pending update first seen "+daysAgo(*m.OldestPendingDays))
	}
	switch {
	case m.RebootRequired == nil:
	case *m.RebootRequired:
		parts = append(parts, strings.Join(f.Reboot.Reasons, "; ")+": reboot required")
	default:
		parts = append(parts, "no reboot needed")
	}
	if m.UpdateInProgress {
		parts = append(parts, "a package manager is running")
	}
	return strings.Join(parts, "; ")
}

// countIgnored counts security updates held back by IgnorePkg.
func countIgnored(list []types.PackageUpdate) int {
	n := 0
	for _, u := range list {
		if u.Ignored {
			n++
		}
	}
	return n
}

// nameList returns " (a, b, c, ...)" for up to three names, or "".
func nameList(list []types.PackageUpdate) string {
	if len(list) == 0 {
		return ""
	}
	names := make([]string, 0, 4)
	for i, u := range list {
		if i == 3 {
			names = append(names, "...")
			break
		}
		names = append(names, u.Name)
	}
	return " (" + strings.Join(names, ", ") + ")"
}

func copyPackageMetrics(m types.PackageMetrics) types.PackageMetrics {
	out := m
	out.NeedsUpdateReasons = append([]string(nil), m.NeedsUpdateReasons...)
	out.RebootReasons = append([]string(nil), m.RebootReasons...)
	if m.SecurityUpdates != nil {
		out.SecurityUpdates = make([]types.PackageUpdate, len(m.SecurityUpdates))
		for i, u := range m.SecurityUpdates {
			u.Issues = append([]string(nil), u.Issues...)
			out.SecurityUpdates[i] = u
		}
	}
	return out
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func daysBetween(then, now time.Time) int {
	d := int(now.Sub(then) / (24 * time.Hour))
	if d < 0 {
		return 0
	}
	return d
}

func daysAgo(d int) string {
	switch d {
	case 0:
		return "today"
	case 1:
		return "1 day ago"
	default:
		return fmt.Sprintf("%d days ago", d)
	}
}

func span(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

func ago(d time.Duration) string { return span(d) + " ago" }

func roundTo(v float64, places int) float64 {
	p := 1.0
	for i := 0; i < places; i++ {
		p *= 10
	}
	if v < 0 {
		return float64(int64(v*p-0.5)) / p
	}
	return float64(int64(v*p+0.5)) / p
}
