package collectors

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/accelerated-industries/gasp/internal/config"
	"github.com/accelerated-industries/gasp/internal/types"
)

// fakeRunner answers commands from a table. Keys are the command line
// joined with spaces.
type fakeRunner struct {
	mu        sync.Mutex
	installed map[string]bool
	responses map[string]func(ctx context.Context) (cmdResult, error)
	calls     []string
	envs      [][]string
}

func newFakeRunner(installed ...string) *fakeRunner {
	r := &fakeRunner{installed: map[string]bool{}, responses: map[string]func(context.Context) (cmdResult, error){}}
	for _, n := range installed {
		r.installed[n] = true
	}
	return r
}

func (r *fakeRunner) set(cmd string, res cmdResult, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.responses[cmd] = func(context.Context) (cmdResult, error) { return res, err }
}

func (r *fakeRunner) setFunc(cmd string, f func(ctx context.Context) (cmdResult, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.responses[cmd] = f
}

func (r *fakeRunner) LookPath(name string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.installed[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

func (r *fakeRunner) Run(ctx context.Context, env []string, name string, args ...string) (cmdResult, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	r.mu.Lock()
	r.calls = append(r.calls, key)
	r.envs = append(r.envs, env)
	f, ok := r.responses[key]
	r.mu.Unlock()
	if !ok {
		return cmdResult{ExitCode: 127, Stderr: []byte("unexpected command " + key)}, nil
	}
	return f(ctx)
}

func (r *fakeRunner) count(cmd string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if c == cmd {
			n++
		}
	}
	return n
}

const aptCmd = "apt-get -s -q -o Dir::Log::Planner=/dev/null dist-upgrade"

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func aptRoot(t *testing.T) string {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/os-release":            "ID=ubuntu\nID_LIKE=debian\n",
		"proc/sys/kernel/osrelease": "6.8.0-49-generic\n",
		"proc/1/comm":               "systemd\n",
		"run":                       "<dir>",
		"var/lib/dpkg/status":       "",
	})
	return root
}

func archRoot(t *testing.T) string {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/os-release":                 "ID=arch\n",
		"proc/sys/kernel/osrelease":      "6.12.8-arch1-1\n",
		"proc/1/comm":                    "systemd\n",
		"run":                            "<dir>",
		"usr/lib/modules/6.12.8-arch1-1": "<dir>",
		"var/lib/pacman/sync/core.db":    "x",
	})
	return root
}

func testSettings() config.PackageSettings {
	s := config.PackagesConfig{}.Resolve()
	s.NetworkJitter = 0
	return s
}

func collectPkgs(t *testing.T, c *PackageCollector) types.PackageMetrics {
	t.Helper()
	data, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	return data.(types.PackageMetrics)
}

// newTestCollector builds a collector without starting its goroutine, so
// tests can drive refresh by hand.
func newTestCollector(t *testing.T, root string, r *fakeRunner, clock *fakeClock, stateDir string) *PackageCollector {
	c := newPackageCollector(testSettings(), stateDir, pkgFS{root: root}, r, clock.now)
	c.startOnce.Do(func() {}) // keep Collect from starting the goroutine
	if c.backend != nil {
		c.loadState()
		c.networkSupported = c.settings.AllowNetwork && c.backend.Name() == "pacman"
		c.scheduleFirstNetwork()
	}
	return c
}

func TestPackageCollectorUnsupported(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"etc/os-release": "ID=alpine\n"})
	c := newPackageCollector(testSettings(), "", pkgFS{root: root}, newFakeRunner(), time.Now)
	m := collectPkgs(t, c)
	if m.Status != "unsupported" || m.Manager != "unknown" || m.State != "unknown" || m.NeedsUpdate {
		t.Errorf("got %+v", m)
	}
	c.Stop()
}

func TestPackageCollectorDetectsDerivative(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"etc/os-release": "ID=endeavouros\nID_LIKE=arch\n"})
	c := newPackageCollector(testSettings(), "", pkgFS{root: root}, newFakeRunner("pacman"), time.Now)
	if c.manager != "pacman" {
		t.Errorf("manager = %q, want pacman", c.manager)
	}
	// os-release says debian but apt-get is missing: fall back to probing.
	writeTree(t, root, map[string]string{"etc/os-release": "ID=debian\n"})
	c = newPackageCollector(testSettings(), "", pkgFS{root: root}, newFakeRunner("pacman"), time.Now)
	if c.manager != "pacman" {
		t.Errorf("manager = %q, want pacman from probing", c.manager)
	}
}

func TestPackageCollectorStatusTransitions(t *testing.T) {
	root := aptRoot(t)
	r := newFakeRunner("apt-get")
	clock := &fakeClock{t: rollupNow}
	c := newTestCollector(t, root, r, clock, "")

	if m := collectPkgs(t, c); m.Status != "pending" || m.State != "unknown" {
		t.Fatalf("before first check: %+v", m)
	}

	// Never succeeded: error, counts null.
	r.set(aptCmd, cmdResult{ExitCode: 100, Stderr: []byte("E: Could not open lock file\n")}, nil)
	c.refresh(context.Background(), true)
	m := collectPkgs(t, c)
	if m.Status != "error" || m.UpdatesPending != nil || !strings.Contains(m.Error, "exited 100") {
		t.Fatalf("first failure: status=%s pending=%v err=%q", m.Status, m.UpdatesPending, m.Error)
	}

	// Success.
	r.set(aptCmd, cmdResult{Stdout: readFixture(t, "apt-ubuntu-2404.txt")}, nil)
	c.refresh(context.Background(), true)
	m = collectPkgs(t, c)
	if m.Status != "ok" || *m.UpdatesPending != 32 || *m.SecurityUpdatesPending != 20 || m.State != "security_updates_pending" || m.Error != "" {
		t.Fatalf("success: %+v", m)
	}

	// Timeout: keep the last values, status stale.
	r.setFunc(aptCmd, func(ctx context.Context) (cmdResult, error) { return cmdResult{}, context.DeadlineExceeded })
	clock.add(2 * time.Hour)
	c.refresh(context.Background(), false)
	m = collectPkgs(t, c)
	if m.Status != "stale" || *m.UpdatesPending != 32 || m.Error == "" {
		t.Fatalf("stale: status=%s pending=%v err=%q", m.Status, m.UpdatesPending, m.Error)
	}

	// Recovery.
	r.set(aptCmd, cmdResult{Stdout: []byte("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")}, nil)
	clock.add(2 * time.Hour)
	c.refresh(context.Background(), false)
	m = collectPkgs(t, c)
	if m.Status != "ok" || *m.UpdatesPending != 0 || m.State != "up_to_date" || m.Error != "" {
		t.Fatalf("recovered: %+v", m)
	}
}

func TestPackageCollectorSkipsUnchangedState(t *testing.T) {
	root := aptRoot(t)
	r := newFakeRunner("apt-get")
	r.set(aptCmd, cmdResult{Stdout: []byte("")}, nil)
	clock := &fakeClock{t: rollupNow}
	c := newTestCollector(t, root, r, clock, "")

	c.refresh(context.Background(), true)
	clock.add(10 * time.Minute)
	c.refresh(context.Background(), false)
	if n := r.count(aptCmd); n != 1 {
		t.Fatalf("ran %d times; an unchanged system within the hour should not re-run", n)
	}

	// dpkg status changed (someone upgraded): re-run at once.
	later := clock.now().Add(time.Minute)
	if err := os.Chtimes(filepath.Join(root, "var/lib/dpkg/status"), later, later); err != nil {
		t.Fatal(err)
	}
	c.refresh(context.Background(), false)
	if n := r.count(aptCmd); n != 2 {
		t.Fatalf("ran %d times; a changed dpkg status should re-run", n)
	}

	// Otherwise hourly.
	clock.add(61 * time.Minute)
	c.refresh(context.Background(), false)
	if n := r.count(aptCmd); n != 3 {
		t.Fatalf("ran %d times; should re-run after refresh_interval", n)
	}
}

func TestPackageCollectorUpdateInProgress(t *testing.T) {
	root := aptRoot(t)
	writeTree(t, root, map[string]string{"proc/4242/comm": "unattended-upgr\n"})
	r := newFakeRunner("apt-get")
	r.set(aptCmd, cmdResult{}, nil)
	clock := &fakeClock{t: rollupNow}
	c := newTestCollector(t, root, r, clock, "")

	c.refresh(context.Background(), true)
	m := collectPkgs(t, c)
	if !m.UpdateInProgress || r.count(aptCmd) != 0 {
		t.Fatalf("in progress=%v, apt runs=%d", m.UpdateInProgress, r.count(aptCmd))
	}

	os.RemoveAll(filepath.Join(root, "proc/4242"))
	c.refresh(context.Background(), false)
	if m = collectPkgs(t, c); m.UpdateInProgress || r.count(aptCmd) != 1 {
		t.Fatalf("after: in progress=%v, apt runs=%d", m.UpdateInProgress, r.count(aptCmd))
	}
}

func TestPackageCollectNeverBlocks(t *testing.T) {
	root := aptRoot(t)
	r := newFakeRunner("apt-get")
	release := make(chan struct{})
	r.setFunc(aptCmd, func(ctx context.Context) (cmdResult, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return cmdResult{}, nil
	})
	c := newPackageCollector(testSettings(), "", pkgFS{root: root}, r, time.Now)
	c.Start()
	defer func() { close(release); c.Stop() }()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			data, err := c.Collect()
			if err != nil {
				t.Errorf("Collect error: %v", err)
			}
			if d := time.Since(start); d > 10*time.Millisecond {
				t.Errorf("Collect took %v while a check was running", d)
			}
			if m := data.(types.PackageMetrics); m.Status != "pending" {
				t.Errorf("status = %s, want pending", m.Status)
			}
		}()
	}
	wg.Wait()
}

func TestPackageCollectorFirstSeenSurvivesRestart(t *testing.T) {
	root := aptRoot(t)
	stateDir := t.TempDir()
	r := newFakeRunner("apt-get")
	two := "Inst a [1] (2 Ubuntu:24.04/noble-updates [amd64])\nInst b [1] (2 Ubuntu:24.04/noble-updates [amd64])\n"
	r.set(aptCmd, cmdResult{Stdout: []byte(two)}, nil)
	clock := &fakeClock{t: rollupNow}

	c := newTestCollector(t, root, r, clock, stateDir)
	c.refresh(context.Background(), true)

	// Restart 20 days later: the clock keeps running from the first sighting.
	clock.add(days(20))
	c = newTestCollector(t, root, r, clock, stateDir)
	c.refresh(context.Background(), true)
	m := collectPkgs(t, c)
	if m.OldestPendingDays == nil || *m.OldestPendingDays != 20 {
		t.Fatalf("oldest pending = %v, want 20", m.OldestPendingDays)
	}

	// a is installed; b gets a newer version: both clocks restart.
	r.set(aptCmd, cmdResult{Stdout: []byte("Inst b [1] (3 Ubuntu:24.04/noble-updates [amd64])\n")}, nil)
	clock.add(time.Hour)
	c.refresh(context.Background(), true)
	m = collectPkgs(t, c)
	if *m.OldestPendingDays != 0 {
		t.Fatalf("oldest pending = %d, want 0", *m.OldestPendingDays)
	}
	if len(c.state.FirstSeen) != 1 {
		t.Errorf("first seen = %v, want only b@3", c.state.FirstSeen)
	}
	if _, err := os.Stat(filepath.Join(stateDir, packagesStateFile)); err != nil {
		t.Errorf("state file not written: %v", err)
	}
	if matches, _ := filepath.Glob(filepath.Join(stateDir, "*.tmp")); len(matches) != 0 {
		t.Errorf("temp files left behind: %v", matches)
	}
}

func setupPacman(r *fakeRunner) {
	r.set("checkupdates", cmdResult{Stdout: []byte("openssl 3.4.0-1 -> 3.4.1-1\ncurl 8.11.0-1 -> 8.11.1-1\nglibc 2.40-1 -> 2.40-2\n")}, nil)
	r.set("pacman -Qu", cmdResult{Stdout: []byte("openssl 3.4.0-1 -> 3.4.1-1\n")}, nil)
}

func TestPacmanNetworkCheckWithArchAudit(t *testing.T) {
	root := archRoot(t)
	stateDir := t.TempDir()
	r := newFakeRunner("pacman", "checkupdates", "arch-audit")
	setupPacman(r)
	dbDir := filepath.Join(stateDir, "checkup-db")
	r.set("arch-audit --format "+archAuditFormat, cmdResult{Stdout: readFixture(t, "arch-audit-format.txt")}, nil)
	clock := &fakeClock{t: time.Date(2026, 11, 25, 12, 0, 0, 0, time.Local)}

	c := newTestCollector(t, root, r, clock, stateDir)
	c.refresh(context.Background(), true)
	m := collectPkgs(t, c)
	if r.count("checkupdates") != 1 {
		t.Fatalf("startup with no previous network check should run checkupdates; calls=%v", r.calls)
	}
	if *m.UpdatesPending != 3 || m.SecurityUpdatesPending == nil || *m.SecurityUpdatesPending != 2 {
		t.Fatalf("pending=%v security=%v (openssl and glibc fixable; curl's fix is testing-only)", m.UpdatesPending, m.SecurityUpdatesPending)
	}
	if m.SecurityMaxSeverity != "critical" || *m.VulnerableUnfixed != 2 || m.LastNetworkCheck == nil {
		t.Errorf("severity=%q unfixed=%v lastNetwork=%v", m.SecurityMaxSeverity, m.VulnerableUnfixed, m.LastNetworkCheck)
	}
	for i, call := range r.calls {
		if call == "checkupdates" && (len(r.envs[i]) != 1 || r.envs[i][0] != "CHECKUPDATES_DB="+dbDir) {
			t.Errorf("checkupdates env = %v", r.envs[i])
		}
	}

	// Later the same day the private db exists; local checks use --nosync
	// and keep the audit findings for packages still pending.
	writeTree(t, stateDir, map[string]string{"checkup-db/sync": "<dir>"})
	r.set("checkupdates --nosync", cmdResult{Stdout: []byte("glibc 2.40-1 -> 2.40-2\n")}, nil)
	clock.add(2 * time.Hour)
	c.refresh(context.Background(), false)
	m = collectPkgs(t, c)
	if r.count("checkupdates") != 1 || r.count("checkupdates --nosync") != 1 {
		t.Fatalf("calls = %v", r.calls)
	}
	if *m.UpdatesPending != 1 || *m.SecurityUpdatesPending != 1 || m.SecurityUpdates[0].Name != "glibc" {
		t.Fatalf("after upgrading openssl: pending=%d security=%d %+v", *m.UpdatesPending, *m.SecurityUpdatesPending, m.SecurityUpdates)
	}
	if strings.Contains(m.Method, "pacman -Qu") || !strings.Contains(m.Method, "arch-audit") {
		t.Errorf("method = %q", m.Method)
	}

	// A restart within 24h does not hit the network, and remembers the
	// audit findings.
	c = newTestCollector(t, root, r, clock, stateDir)
	c.refresh(context.Background(), true)
	m = collectPkgs(t, c)
	if r.count("checkupdates") != 1 {
		t.Fatalf("restart within 24h ran checkupdates again: %v", r.calls)
	}
	if m.SecurityUpdatesPending == nil || *m.SecurityUpdatesPending != 1 {
		t.Fatalf("audit findings lost on restart: %v", m.SecurityUpdatesPending)
	}
}

// An arch-audit without --format exits with a usage error; GASP falls back
// to the sentence output.
func TestPacmanArchAuditFallsBackToText(t *testing.T) {
	r := newFakeRunner("pacman", "checkupdates", "arch-audit")
	setupPacman(r)
	r.set("arch-audit --format "+archAuditFormat, cmdResult{ExitCode: 1, Stderr: []byte("error: Found argument '--format' which wasn't expected")}, nil)
	r.set("arch-audit", cmdResult{Stdout: readFixture(t, "arch-audit.txt")}, nil)
	p := &pacmanBackend{runner: r}
	out, err := p.NetworkCheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !out.SecurityKnown || len(out.Security) != 2 || len(out.Unfixed) != 2 {
		t.Fatalf("security=%+v unfixed=%+v known=%v", out.Security, out.Unfixed, out.SecurityKnown)
	}
}

// Output GASP cannot read must not turn into "no security issues".
func TestPacmanArchAuditUnreadableOutput(t *testing.T) {
	r := newFakeRunner("pacman", "checkupdates", "arch-audit")
	setupPacman(r)
	garbled := cmdResult{Stdout: []byte("Some new format nobody told GASP about\n")}
	r.set("arch-audit --format "+archAuditFormat, garbled, nil)
	r.set("arch-audit", garbled, nil)
	p := &pacmanBackend{runner: r}
	out, err := p.NetworkCheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.SecurityKnown || out.Security != nil {
		t.Fatalf("unreadable output reported as known: %+v", out)
	}

	// With findings from an earlier run, a later unreadable run keeps them.
	r.set("arch-audit --format "+archAuditFormat, cmdResult{Stdout: readFixture(t, "arch-audit-format.txt")}, nil)
	if out, _ = p.NetworkCheck(context.Background()); len(out.Security) != 2 {
		t.Fatalf("first audit: %+v", out.Security)
	}
	r.set("arch-audit --format "+archAuditFormat, garbled, nil)
	if out, _ = p.NetworkCheck(context.Background()); !out.SecurityKnown || len(out.Security) != 2 {
		t.Fatalf("previous findings lost: %+v", out.Security)
	}
}

func TestPacmanWithoutArchAuditOrNetwork(t *testing.T) {
	root := archRoot(t)
	r := newFakeRunner("pacman")
	r.set("pacman -Qu", cmdResult{ExitCode: 1}, nil) // nothing to update
	clock := &fakeClock{t: rollupNow}
	c := newTestCollector(t, root, r, clock, "")
	c.refresh(context.Background(), true)
	m := collectPkgs(t, c)
	if m.Status != "ok" || *m.UpdatesPending != 0 || m.SecurityUpdatesPending != nil || m.Method != "pacman -Qu" {
		t.Fatalf("got status=%s pending=%v sec=%v method=%q", m.Status, m.UpdatesPending, m.SecurityUpdatesPending, m.Method)
	}
	if r.count("checkupdates") != 0 || r.count("arch-audit") != 0 {
		t.Errorf("ran tools that are not installed: %v", r.calls)
	}
	if !strings.Contains(m.Interpretation, "install arch-audit") {
		t.Errorf("interpretation = %q", m.Interpretation)
	}
}

func TestPacmanNetworkSchedule(t *testing.T) {
	root := archRoot(t)
	stateDir := t.TempDir()
	r := newFakeRunner("pacman", "checkupdates")
	setupPacman(r)
	writeTree(t, stateDir, map[string]string{"checkup-db/sync": "<dir>"})
	r.set("checkupdates --nosync", cmdResult{ExitCode: 2}, nil)

	// The last network check was 10 hours ago: no network at startup.
	start := time.Date(2026, 11, 25, 12, 0, 0, 0, time.Local)
	last := start.Add(-10 * time.Hour)
	writeTree(t, stateDir, map[string]string{packagesStateFile: `{"last_network_check":"` + last.Format(time.RFC3339Nano) + `","first_seen":{}}`})
	clock := &fakeClock{t: start}
	c := newTestCollector(t, root, r, clock, stateDir)
	c.refresh(context.Background(), true)
	if r.count("checkupdates") != 0 {
		t.Fatalf("network check ran at startup though the last was 10h ago")
	}
	want := time.Date(2026, 11, 26, 3, 30, 0, 0, time.Local)
	if !c.nextNetwork.Equal(want) {
		t.Fatalf("next network check = %v, want %v", c.nextNetwork, want)
	}

	// Tick through the night every 5 minutes: exactly one network check, at 03:30.
	for clock.now().Before(time.Date(2026, 11, 26, 12, 0, 0, 0, time.Local)) {
		clock.add(5 * time.Minute)
		before := r.count("checkupdates")
		c.refresh(context.Background(), false)
		if r.count("checkupdates") > before {
			if got := clock.now(); got.Before(want) || got.After(want.Add(5*time.Minute)) {
				t.Errorf("network check ran at %v, want soon after %v", got, want)
			}
		}
	}
	if n := r.count("checkupdates"); n != 1 {
		t.Fatalf("network checks in a day = %d, want 1", n)
	}

	// A failed network check retries in an hour, and local data still answers.
	r.set("checkupdates", cmdResult{ExitCode: 1, Stderr: []byte("==> ERROR: Cannot fetch updates\n")}, nil)
	c.nextNetwork = clock.now()
	c.refresh(context.Background(), false)
	m := collectPkgs(t, c)
	if m.Status != "stale" || !strings.Contains(m.Error, "network check failed") || m.UpdatesPending == nil {
		t.Errorf("after network failure: status=%s err=%q pending=%v", m.Status, m.Error, m.UpdatesPending)
	}
	if got := c.nextNetwork.Sub(clock.now()); got != networkRetryDelay {
		t.Errorf("retry in %v, want %v", got, networkRetryDelay)
	}

	// allow_network: false never runs it.
	c2 := newPackageCollector(func() config.PackageSettings { s := testSettings(); s.AllowNetwork = false; return s }(), "", pkgFS{root: root}, r, clock.now)
	c2.startOnce.Do(func() {})
	c2.networkSupported = c2.settings.AllowNetwork && c2.backend.Name() == "pacman"
	if c2.networkSupported {
		t.Error("allow_network false still enables the network check")
	}
}

func TestManagerPackageSummary(t *testing.T) {
	m := &Manager{hostname: "test", startTime: time.Now()}
	upgraded := time.Now().Add(-6 * time.Hour)
	results := make(chan CollectorResult, 1)
	results <- CollectorResult{Name: "packages", Data: types.PackageMetrics{
		Manager: "apt", State: "security_updates_pending", NeedsUpdate: true,
		NeedsUpdateReasons: []string{"3 security updates pending", "reboot required: x"},
		LastUpgrade:        &upgraded, ScorePenalty: 15,
	}}
	close(results)
	snap, err := m.assembleSnapshot(results)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Packages == nil || snap.Packages.Manager != "apt" {
		t.Fatalf("packages block missing: %+v", snap.Packages)
	}
	if snap.Summary.Score != 85 || len(snap.Summary.Concerns) != 2 {
		t.Errorf("score=%d concerns=%v", snap.Summary.Score, snap.Summary.Concerns)
	}
	if len(snap.Summary.RecentChanges) != 1 || snap.Summary.RecentChanges[0] != "System package update completed 6h ago" {
		t.Errorf("recent changes = %v", snap.Summary.RecentChanges)
	}
}
