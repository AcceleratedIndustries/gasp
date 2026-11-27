package collectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/accelerated-industries/gasp/internal/config"
	"github.com/accelerated-industries/gasp/internal/types"
)

// writeTree creates files under root. A value of "<dir>" makes a directory.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, content := range files {
		full := filepath.Join(root, p)
		if content == "<dir>" {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDetectReboot(t *testing.T) {
	cases := []struct {
		name     string
		files    map[string]string
		keepsOld bool
		known    bool
		required bool
		reason   string
	}{
		{
			name: "debian flag file with packages",
			files: map[string]string{
				"proc/sys/kernel/osrelease": "6.1.0-27-amd64\n",
				"run/reboot-required":       "*** System restart required ***\n",
				"run/reboot-required.pkgs":  "linux-image-6.1.0-28-amd64\nlibc6\nlibc6\n",
				"var/lib/dpkg":              "<dir>",
			},
			keepsOld: true, known: true, required: true,
			reason: "requested by linux-image-6.1.0-28-amd64, libc6",
		},
		{
			name: "debian, no flag, same kernel",
			files: map[string]string{
				"proc/sys/kernel/osrelease":            "6.1.0-27-amd64\n",
				"run":                                  "<dir>",
				"var/lib/dpkg":                         "<dir>",
				"usr/lib/modules/6.1.0-27-amd64":       "<dir>",
				"boot/vmlinuz-6.1.0-27-amd64":          "x",
				"usr/lib/modules/6.1.0-27-cloud-amd64": "<dir>",
				"boot/vmlinuz-6.1.0-28-cloud-amd64":    "x",
			},
			keepsOld: true, known: true, required: false,
		},
		{
			name: "ubuntu newer kernel installed",
			files: map[string]string{
				"proc/sys/kernel/osrelease":        "6.8.0-49-generic\n",
				"run":                              "<dir>",
				"var/lib/dpkg":                     "<dir>",
				"usr/lib/modules/6.8.0-49-generic": "<dir>",
				"usr/lib/modules/6.8.0-51-generic": "<dir>",
				"boot/vmlinuz-6.8.0-49-generic":    "x",
				"boot/vmlinuz-6.8.0-51-generic":    "x",
			},
			keepsOld: true, known: true, required: true,
			reason: "newer kernel 6.8.0-51-generic is installed (running 6.8.0-49-generic)",
		},
		{
			name: "leftover modules dir without a kernel image is ignored",
			files: map[string]string{
				"proc/sys/kernel/osrelease":        "6.8.0-49-generic\n",
				"usr/lib/modules/6.8.0-49-generic": "<dir>",
				"usr/lib/modules/6.8.0-51-generic": "<dir>",
				"boot/vmlinuz-6.8.0-49-generic":    "x",
			},
			keepsOld: true, known: true, required: false,
		},
		{
			name: "arch kernel replaced in place",
			files: map[string]string{
				"proc/sys/kernel/osrelease":      "6.12.4-arch1-1\n",
				"run":                            "<dir>",
				"usr/lib/modules/6.12.8-arch1-1": "<dir>",
			},
			keepsOld: false, known: true, required: true,
			reason: "running kernel 6.12.4-arch1-1 is no longer installed",
		},
		{
			name: "arch up to date",
			files: map[string]string{
				"proc/sys/kernel/osrelease":      "6.12.8-arch1-1\n",
				"run":                            "<dir>",
				"usr/lib/modules/6.12.8-arch1-1": "<dir>",
			},
			keepsOld: false, known: true, required: false,
		},
		{
			name: "container: no modules, not debian",
			files: map[string]string{
				"proc/sys/kernel/osrelease": "6.18.0-host\n",
				"run":                       "<dir>",
			},
			keepsOld: false, known: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			writeTree(t, root, c.files)
			st := detectReboot(pkgFS{root: root}, c.keepsOld)
			if st.Known != c.known || st.Required != c.required {
				t.Fatalf("known=%v required=%v reasons=%v, want known=%v required=%v", st.Known, st.Required, st.Reasons, c.known, c.required)
			}
			if c.reason != "" && !strings.Contains(strings.Join(st.Reasons, "; "), c.reason) {
				t.Errorf("reasons = %v, want %q", st.Reasons, c.reason)
			}
		})
	}
}

var rollupNow = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func pendingN(n int) []pendingPackage {
	out := make([]pendingPackage, n)
	for i := range out {
		out[i] = pendingPackage{Name: "pkg" + string(rune('a'+i)), Installed: "1", Available: "2"}
	}
	return out
}

func baseFacts(manager string, pending int) pkgFacts {
	return pkgFacts{
		Manager:       manager,
		Result:        &checkResult{Method: "test", Pending: pendingN(pending), SecurityKnown: true},
		LastSuccess:   rollupNow,
		EverSucceeded: true,
		Reboot:        rebootStatus{Known: true},
		MetadataTime:  rollupNow.Add(-5 * time.Hour),
		HaveMetadata:  true,
		LastUpgrade:   rollupNow.Add(-days(2)),
		HaveUpgrade:   true,
	}
}

func TestEvaluatePackages(t *testing.T) {
	def := config.PackagesConfig{}.Resolve()
	sec := func(f pkgFacts, n int) pkgFacts {
		for i := 0; i < n; i++ {
			f.Result.Pending[i].Security = true
			f.Result.Security = append(f.Result.Security, types.PackageUpdate{Name: f.Result.Pending[i].Name, Severity: "high"})
		}
		return f
	}
	upgradedAgo := func(f pkgFacts, d time.Duration) pkgFacts { f.LastUpgrade = rollupNow.Add(-d); return f }
	waiting := func(f pkgFacts, d time.Duration) pkgFacts {
		f.LastUpgrade, f.HaveUpgrade = time.Time{}, false
		f.OldestPending, f.HavePendingAge = d, true
		return f
	}

	cases := []struct {
		name    string
		facts   pkgFacts
		cfg     config.PackageSettings
		state   string
		flag    bool
		reasons int
		penalty int
	}{
		{"up to date", baseFacts("apt", 0), def, "up_to_date", false, 0, 0},
		{"routine updates never flag", baseFacts("apt", 12), def, "updates_pending", false, 0, 0},
		{"security flags", sec(baseFacts("apt", 5), 2), def, "security_updates_pending", true, 1, 10},
		{"reboot flags", func() pkgFacts {
			f := baseFacts("pacman", 0)
			f.Reboot = rebootStatus{Known: true, Required: true, Reasons: []string{"running kernel 6.12.4 is no longer installed"}}
			return f
		}(), def, "reboot_required", true, 1, 5},
		{"pacman 6 days not overdue", upgradedAgo(baseFacts("pacman", 3), days(6)), def, "updates_pending", false, 0, 0},
		{"pacman 7 days overdue", upgradedAgo(baseFacts("pacman", 3), days(7)), def, "overdue", true, 1, 5},
		{"pacman 8 days overdue", upgradedAgo(baseFacts("pacman", 3), days(8)), def, "overdue", true, 1, 5},
		{"apt 29 days not overdue", upgradedAgo(baseFacts("apt", 3), days(29)), def, "updates_pending", false, 0, 0},
		{"apt 30 days overdue", upgradedAgo(baseFacts("apt", 3), days(30)), def, "overdue", true, 1, 5},
		{"apt 31 days overdue", upgradedAgo(baseFacts("apt", 3), days(31)), def, "overdue", true, 1, 5},
		{"no upgrade in 40 days but nothing pending", upgradedAgo(baseFacts("apt", 0), days(40)), def, "up_to_date", false, 0, 0},
		{"no upgrade in 40 days and stale lists", func() pkgFacts {
			f := upgradedAgo(baseFacts("apt", 0), days(40))
			f.MetadataTime = rollupNow.Add(-days(20))
			return f
		}(), def, "overdue", true, 1, 5},
		{"pending update waiting 7 days on pacman", waiting(baseFacts("pacman", 2), days(7)), def, "overdue", true, 1, 5},
		{"pending update waiting 6 days on pacman", waiting(baseFacts("pacman", 2), days(6)), def, "updates_pending", false, 0, 0},
		{"override beats default", upgradedAgo(baseFacts("apt", 3), days(10)), config.PackagesConfig{
			OverdueAfter: map[string]time.Duration{"apt": days(10)},
		}.Resolve(), "overdue", true, 1, 5},
		{"all three triggers, custom penalties", func() pkgFacts {
			f := upgradedAgo(sec(baseFacts("apt", 4), 1), days(45))
			f.Reboot = rebootStatus{Known: true, Required: true, Reasons: []string{"x"}}
			return f
		}(), config.PackagesConfig{ScorePenalty: config.ScorePenaltyConfig{Security: intPtr(20), Reboot: intPtr(7), Overdue: intPtr(3)}}.Resolve(),
			"security_updates_pending", true, 3, 30},
		{"no successful check yet", pkgFacts{Manager: "apt", Reboot: rebootStatus{Known: true}}, def, "unknown", false, 0, 0},
		{"security unknown never flags", func() pkgFacts {
			f := baseFacts("pacman", 5)
			f.Result.SecurityKnown = false
			return f
		}(), def, "updates_pending", false, 0, 0},
		{"no reboot signal never flags", func() pkgFacts {
			f := baseFacts("apt", 0)
			f.Reboot = rebootStatus{}
			return f
		}(), def, "up_to_date", false, 0, 0},
		{"no upgrade log never flags age", func() pkgFacts {
			f := baseFacts("pacman", 4)
			f.HaveUpgrade = false
			return f
		}(), def, "updates_pending", false, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := evaluatePackages(c.facts, c.cfg, rollupNow)
			if m.State != c.state || m.NeedsUpdate != c.flag || len(m.NeedsUpdateReasons) != c.reasons || m.ScorePenalty != c.penalty {
				t.Errorf("state=%s flag=%v reasons=%v penalty=%d\nwant state=%s flag=%v reasons=%d penalty=%d\ninterpretation: %s",
					m.State, m.NeedsUpdate, m.NeedsUpdateReasons, m.ScorePenalty, c.state, c.flag, c.reasons, c.penalty, m.Interpretation)
			}
		})
	}
}

func intPtr(n int) *int { return &n }

func TestEvaluatePackagesNullsAndListing(t *testing.T) {
	def := config.PackagesConfig{}.Resolve()

	// Before any check: counts are null, not zero.
	m := evaluatePackages(pkgFacts{Manager: "apt"}, def, rollupNow)
	if m.UpdatesPending != nil || m.SecurityUpdatesPending != nil || m.Status != "pending" {
		t.Errorf("pending check: %+v", m)
	}
	m = evaluatePackages(pkgFacts{Manager: "apt", Error: "apt-get exited 100"}, def, rollupNow)
	if m.Status != "error" || m.UpdatesPending != nil {
		t.Errorf("never succeeded: status=%s pending=%v", m.Status, m.UpdatesPending)
	}

	// Security unknown: null, and the interpretation gives the real cause.
	for _, tc := range []struct {
		why        string
		networkOff bool
		want       string
	}{
		{whyNoAudit, false, "security status unknown (install arch-audit to check)"},
		{whyAuditFailed, false, "security status unknown (arch-audit's output could not be read; see the log)"},
		{whyAuditNotRun, false, "security status unknown (arch-audit runs with the daily network check, which has not run yet)"},
		{whyAuditNotRun, true, "security status unknown (arch-audit runs only with the network check, which is off)"},
		{"", false, "security status unknown;"},
	} {
		f := baseFacts("pacman", 3)
		f.Result.SecurityKnown = false
		f.Result.SecurityUnknownWhy = tc.why
		f.NetworkOff = tc.networkOff
		m = evaluatePackages(f, def, rollupNow)
		if m.SecurityUpdatesPending != nil || !strings.Contains(m.Interpretation, tc.want) {
			t.Errorf("why=%q off=%v: sec=%v %q", tc.why, tc.networkOff, m.SecurityUpdatesPending, m.Interpretation)
		}
		if tc.why != whyNoAudit && strings.Contains(m.Interpretation, "install arch-audit") {
			t.Errorf("why=%q: suggests installing arch-audit: %q", tc.why, m.Interpretation)
		}
	}
	f := baseFacts("pacman", 3)

	// Only security updates are named, sorted by severity, capped.
	f = baseFacts("pacman", 4)
	f.Result.Security = []types.PackageUpdate{
		{Name: "curl", Severity: "medium"}, {Name: "glibc", Severity: "critical"}, {Name: "openssl", Severity: "high"},
	}
	f.Result.Unfixed = []types.PackageUpdate{{Name: "libxml2", Severity: "low"}}
	s := def
	s.MaxListed = 2
	m = evaluatePackages(f, s, rollupNow)
	if len(m.SecurityUpdates) != 2 || m.SecurityUpdates[0].Name != "glibc" || m.SecurityUpdates[1].Name != "openssl" {
		t.Errorf("listed = %+v", m.SecurityUpdates)
	}
	if m.SecurityMaxSeverity != "critical" || m.VulnerableUnfixed == nil || *m.VulnerableUnfixed != 1 {
		t.Errorf("severity=%q unfixed=%v", m.SecurityMaxSeverity, m.VulnerableUnfixed)
	}
	if !strings.Contains(m.NeedsUpdateReasons[0], "3 security updates pending (max severity: critical)") {
		t.Errorf("reason = %q", m.NeedsUpdateReasons[0])
	}
	for _, p := range f.Result.Pending {
		if strings.Contains(m.Interpretation, p.Name) {
			t.Errorf("routine package %s named in %q", p.Name, m.Interpretation)
		}
	}

	s.ListSecurityUpdates = false
	if m = evaluatePackages(f, s, rollupNow); m.SecurityUpdates != nil {
		t.Errorf("list_security_updates false still listed %+v", m.SecurityUpdates)
	}

	// Stale lists: note, no concern, no flag.
	f = baseFacts("apt", 0)
	f.MetadataTime = rollupNow.Add(-days(16))
	m = evaluatePackages(f, def, rollupNow)
	if m.NeedsUpdate || !strings.Contains(m.Interpretation, "may be out of date") {
		t.Errorf("stale lists: flag=%v %q", m.NeedsUpdate, m.Interpretation)
	}

	// A failed refresh keeps the last values and says how old they are.
	f = baseFacts("apt", 2)
	f.Error = "apt-get timed out"
	f.LastSuccess = rollupNow.Add(-4 * time.Hour)
	m = evaluatePackages(f, def, rollupNow)
	if m.Status != "stale" || *m.UpdatesPending != 2 || !strings.HasPrefix(m.Interpretation, "last successful check 4h ago") {
		t.Errorf("stale: status=%s %q", m.Status, m.Interpretation)
	}
}

func TestNextDailySlot(t *testing.T) {
	loc := time.UTC
	cases := []struct {
		now, want time.Time
		jitter    time.Duration
	}{
		{time.Date(2026, 11, 25, 1, 0, 0, 0, loc), time.Date(2026, 11, 25, 3, 30, 0, 0, loc), 0},
		{time.Date(2026, 11, 25, 3, 30, 0, 0, loc), time.Date(2026, 11, 26, 3, 30, 0, 0, loc), 0},
		{time.Date(2026, 11, 25, 12, 0, 0, 0, loc), time.Date(2026, 11, 26, 3, 50, 0, 0, loc), 20 * time.Minute},
		{time.Date(2026, 11, 25, 3, 40, 0, 0, loc), time.Date(2026, 11, 25, 3, 50, 0, 0, loc), 20 * time.Minute},
	}
	for _, c := range cases {
		if got := nextDailySlot(c.now, 3, 30, c.jitter); !got.Equal(c.want) {
			t.Errorf("now %v jitter %v: got %v, want %v", c.now, c.jitter, got, c.want)
		}
	}
}

// "Up to date" names what it was checked against.
func TestUpToDateSource(t *testing.T) {
	def := config.PackagesConfig{}.Resolve()
	for _, tc := range []struct {
		method string
		synced time.Duration // 0: no network check recorded
		want   string
	}{
		{"checkupdates + arch-audit", 5 * time.Minute, "up to date per package lists synced 5m ago;"},
		{"checkupdates --nosync + arch-audit", 3 * time.Hour, "up to date per package lists synced 3h ago;"},
		{"checkupdates --nosync", 0, "up to date per GASP's synced package lists;"},
		{"pacman -Qu", 0, "up to date per local pacman database;"},
	} {
		f := baseFacts("pacman", 0)
		f.Result.Method = tc.method
		if tc.synced > 0 {
			f.LastNetworkCheck = rollupNow.Add(-tc.synced)
		}
		m := evaluatePackages(f, def, rollupNow)
		if !strings.HasPrefix(m.Interpretation, tc.want) {
			t.Errorf("%s: %q", tc.method, m.Interpretation)
		}
	}
}
