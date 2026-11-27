//go:build archlive

// Live tests for the pacman backend. They run the real checkupdates,
// arch-audit and pacman on the machine and check that GASP reads their
// output correctly. Run them on an up-to-date Arch machine as a normal user:
//
//	go test -tags archlive -v -count=1 -run Live ./internal/collectors/
//
// Needs pacman, pacman-contrib (checkupdates), fakeroot and arch-audit.
// TestLiveCheckupdates and TestLiveCollector download the package databases
// into a temporary directory (never /var/lib/pacman/sync), and the real
// arch-audit runs download the security tracker. The fake-tracker tests
// read a local file instead. Nothing here installs, upgrades or changes
// packages.
//
// The raw output is logged with -v; save it as new fixtures in
// testdata/packages.
package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/accelerated-industries/gasp/internal/config"
	"github.com/accelerated-industries/gasp/internal/types"
)

func requireArchTools(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		if _, err := exec.LookPath(n); err != nil {
			t.Fatalf("%s not found: install it first (sudo pacman -S --needed pacman-contrib fakeroot arch-audit)", n)
		}
	}
}

func liveRun(t *testing.T, env []string, name string, args ...string) cmdResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := execRunner{}.Run(ctx, env, name, args...)
	if err != nil {
		t.Fatalf("%s %v: %v", name, args, err)
	}
	return res
}

func installedVersion(t *testing.T, pkg string) string {
	t.Helper()
	res := liveRun(t, nil, "pacman", "-Q", pkg)
	f := strings.Fields(string(res.Stdout))
	if res.ExitCode != 0 || len(f) != 2 {
		t.Fatalf("pacman -Q %s: exit %d %q", pkg, res.ExitCode, res.Stdout)
	}
	return f[1]
}

// fakeArchAudit puts a wrapper named arch-audit first on PATH that runs the
// real arch-audit against a fake security tracker file. The output is real
// arch-audit output, about findings the test controls.
func fakeArchAudit(t *testing.T, avgs []map[string]any) {
	t.Helper()
	real, err := exec.LookPath("arch-audit")
	if err != nil {
		t.Fatal("arch-audit not installed")
	}
	dir := t.TempDir()
	data, err := json.Marshal(avgs)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "avgs.json")
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\nexec %q --source %q \"$@\"\n", real, src)
	if err := os.WriteFile(filepath.Join(bin, "arch-audit"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func avg(name, pkg, status, severity, kind string, fixed any, cve string) map[string]any {
	return map[string]any{
		"name": name, "packages": []string{pkg}, "status": status, "severity": severity,
		"type": kind, "fixed": fixed, "issues": []string{cve},
	}
}

func byName(list []types.PackageUpdate) map[string]types.PackageUpdate {
	m := map[string]types.PackageUpdate{}
	for _, u := range list {
		m[u.Name] = u
	}
	return m
}

func names(list []types.PackageUpdate) []string {
	var out []string
	for _, u := range list {
		out = append(out, u.Name)
	}
	sort.Strings(out)
	return out
}

func logOutput(t *testing.T, label string, res cmdResult) {
	t.Helper()
	t.Logf("---- %s (exit %d) ----\n%s", label, res.ExitCode, res.Stdout)
	if len(res.Stderr) > 0 {
		t.Logf("---- %s stderr ----\n%s", label, res.Stderr)
	}
}

// TestLiveArchAuditVersion logs the versions and help text, so a changed
// flag shows up.
func TestLiveArchAuditVersion(t *testing.T) {
	requireArchTools(t, "arch-audit", "checkupdates", "fakeroot")
	logOutput(t, "pacman -Q", liveRun(t, nil, "pacman", "-Q", "pacman", "pacman-contrib", "fakeroot", "arch-audit"))
	help := liveRun(t, nil, "arch-audit", "--help")
	logOutput(t, "arch-audit --help", help)
	for _, flag := range []string{"--format", "--source"} {
		if !strings.Contains(string(help.Stdout)+string(help.Stderr), flag) {
			t.Errorf("arch-audit --help does not list %s", flag)
		}
	}
}

// TestLiveArchAuditFake checks both parsers on real arch-audit output about
// known findings: a released fix, no fix yet, a testing-only fix and a
// package that is not installed.
func TestLiveArchAuditFake(t *testing.T) {
	requireArchTools(t, "arch-audit", "pacman")
	installedVersion(t, "pacman")
	installedVersion(t, "bash")
	installedVersion(t, "coreutils")
	fakeArchAudit(t, []map[string]any{
		avg("AVG-90001", "pacman", "Fixed", "High", "arbitrary code execution", "999.0-1", "CVE-2099-0001"),
		avg("AVG-90002", "bash", "Vulnerable", "Medium", "denial of service", nil, "CVE-2099-0002"),
		avg("AVG-90003", "coreutils", "Testing", "Low", "information disclosure", "999.0-1", "CVE-2099-0003"),
		avg("AVG-90004", "gasp-not-installed-package", "Fixed", "Critical", "privilege escalation", "1.0-1", "CVE-2099-0004"),
	})

	logOutput(t, "arch-audit (fake tracker)", liveRun(t, nil, "arch-audit"))
	logOutput(t, "arch-audit --format (fake tracker)", liveRun(t, nil, "arch-audit", "--format", archAuditFormat))

	p := &pacmanBackend{runner: execRunner{}}
	p.audit(context.Background())
	if !p.securityKnown {
		t.Fatal("audit did not produce a trusted result; see the log line above")
	}
	check := func(label string, fixable, unfixed []types.PackageUpdate) {
		t.Helper()
		if got := names(fixable); len(got) != 1 || got[0] != "pacman" {
			t.Errorf("%s: fixable = %+v, want only pacman", label, fixable)
		}
		if u := byName(fixable)["pacman"]; u.Available != "999.0-1" || u.Severity != "high" {
			t.Errorf("%s: pacman = %+v", label, u)
		}
		if got := names(unfixed); len(got) != 2 || got[0] != "bash" || got[1] != "coreutils" {
			t.Errorf("%s: unfixed = %+v, want bash and coreutils (testing-only fix)", label, unfixed)
		}
		if u := byName(unfixed)["bash"]; u.Severity != "medium" {
			t.Errorf("%s: bash = %+v", label, u)
		}
	}
	check("audit (format)", p.lastSecurity, p.lastUnfixed)
	if u := byName(p.lastSecurity)["pacman"]; len(u.Issues) != 1 || u.Issues[0] != "CVE-2099-0001" {
		t.Errorf("format output should carry CVE ids: %+v", u)
	}

	// The fallback parser must read the same run's sentence output.
	fixable, unfixed, ok := parseArchAuditText(liveRun(t, nil, "arch-audit").Stdout)
	if !ok {
		t.Fatal("parseArchAuditText rejected real arch-audit output")
	}
	check("text", fixable, unfixed)
	fixable, unfixed, ok = parseArchAuditText(liveRun(t, nil, "arch-audit", "-c", "--show-testing").Stdout)
	if !ok {
		t.Fatal("parseArchAuditText rejected arch-audit -c --show-testing output")
	}
	check("text -c --show-testing", fixable, unfixed)
}

// TestLiveArchAuditReal runs arch-audit against the real tracker and checks
// that every package it reports is parsed, by both parsers.
func TestLiveArchAuditReal(t *testing.T) {
	requireArchTools(t, "arch-audit")
	text := liveRun(t, nil, "arch-audit")
	logOutput(t, "arch-audit", text)
	format := liveRun(t, nil, "arch-audit", "--format", archAuditFormat)
	logOutput(t, "arch-audit --format", format)
	if text.ExitCode != 0 || format.ExitCode != 0 {
		t.Fatalf("arch-audit failed: exit %d / %d", text.ExitCode, format.ExitCode)
	}
	var reported []string
	for _, line := range strings.Split(string(text.Stdout), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			name := f[0]
			if name == "Package" && len(f) > 1 {
				name = f[1]
			}
			reported = append(reported, name)
		}
	}
	sort.Strings(reported)

	tf, tu, ok := parseArchAuditText(text.Stdout)
	if !ok {
		t.Fatal("parseArchAuditText rejected real output")
	}
	ff, fu, ok := parseArchAuditFormat(format.Stdout)
	if !ok {
		t.Fatal("parseArchAuditFormat rejected real output")
	}
	textNames := names(append(append([]types.PackageUpdate{}, tf...), tu...))
	formatNames := names(append(append([]types.PackageUpdate{}, ff...), fu...))
	if strings.Join(textNames, ",") != strings.Join(reported, ",") || strings.Join(formatNames, ",") != strings.Join(reported, ",") {
		t.Errorf("arch-audit reported %v\ntext parser: %v\nformat parser: %v", reported, textNames, formatNames)
	}
	if strings.Join(names(tf), ",") != strings.Join(names(ff), ",") {
		t.Errorf("parsers disagree on which have a released fix: text %v, format %v", names(tf), names(ff))
	}
	t.Logf("%d affected packages: %d with a released fix, %d without", len(reported), len(ff), len(fu))
}

// TestLiveCheckupdates runs the real network and local checks against a
// private database copy and compares the counts with the tools' own output.
func TestLiveCheckupdates(t *testing.T) {
	requireArchTools(t, "pacman", "checkupdates", "fakeroot")
	dbDir := filepath.Join(t.TempDir(), "checkup-db")
	p := &pacmanBackend{fs: pkgFS{root: "/"}, runner: execRunner{}, dbDir: dbDir}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	net, err := p.NetworkCheck(ctx)
	if err != nil {
		t.Fatalf("network check: %v", err)
	}
	t.Logf("network check: method=%q pending=%d security=%d unfixed=%d", net.Method, len(net.Pending), len(net.Security), len(net.Unfixed))
	if !dirExists(filepath.Join(dbDir, "sync")) {
		t.Errorf("checkupdates did not create %s/sync", dbDir)
	}

	env := []string{"CHECKUPDATES_DB=" + dbDir}
	raw := liveRun(t, env, "checkupdates", "--nosync")
	logOutput(t, "checkupdates --nosync", raw)
	if raw.ExitCode != 0 && raw.ExitCode != 2 {
		t.Fatalf("checkupdates --nosync exited %d", raw.ExitCode)
	}
	want := 0
	for _, line := range strings.Split(string(raw.Stdout), "\n") {
		if strings.Contains(line, " -> ") {
			want++
		}
	}
	if len(net.Pending) != want {
		t.Errorf("network check found %d pending, checkupdates --nosync lists %d", len(net.Pending), want)
	}

	local, err := p.LocalCheck(ctx)
	if err != nil {
		t.Fatalf("local check: %v", err)
	}
	if !strings.HasPrefix(local.Method, "checkupdates --nosync") || len(local.Pending) != want {
		t.Errorf("local check: method=%q pending=%d, want checkupdates --nosync and %d", local.Method, len(local.Pending), want)
	}

	// pacman -Qu against the system databases: GASP's count must match the
	// lines pacman prints, minus [ignored] ones.
	qu := liveRun(t, nil, "pacman", "-Qu")
	logOutput(t, "pacman -Qu", qu)
	wantQu, wantIgnored := 0, 0
	for _, line := range strings.Split(string(qu.Stdout), "\n") {
		switch {
		case strings.Contains(line, " -> ") && strings.Contains(line, "[ignored]"):
			wantIgnored++
		case strings.Contains(line, " -> "):
			wantQu++
		}
	}
	gotQu, gotIgnored := parsePacmanUpdates(qu.Stdout)
	if len(gotQu) != wantQu || len(gotIgnored) != wantIgnored {
		t.Errorf("pacman -Qu: parsed %d pending and %d ignored, want %d and %d", len(gotQu), len(gotIgnored), wantQu, wantIgnored)
	}

	// Ignored updates against the private copy, which checkupdates hides.
	quDB := liveRun(t, nil, "pacman", "-Qu", "--dbpath", dbDir)
	logOutput(t, "pacman -Qu --dbpath <checkup-db>", quDB)
	_, wantNetIgnored := parsePacmanUpdates(quDB.Stdout)
	if !net.IgnoredKnown || len(net.Ignored) != len(wantNetIgnored) {
		t.Errorf("network check ignored=%d known=%v, pacman -Qu --dbpath lists %d [ignored]", len(net.Ignored), net.IgnoredKnown, len(wantNetIgnored))
	}
	if !local.IgnoredKnown || len(local.Ignored) != len(wantNetIgnored) {
		t.Errorf("local check ignored=%d known=%v, want %d", len(local.Ignored), local.IgnoredKnown, len(wantNetIgnored))
	}
	t.Logf("ignored by IgnorePkg/IgnoreGroup: %d", len(net.Ignored))

	// A pending package with a known fix is marked as a security update.
	if len(net.Pending) == 0 {
		t.Log("nothing pending, so the security marking check is skipped; downgrade a leaf package from /var/cache/pacman/pkg to run it")
		return
	}
	if _, err := exec.LookPath("arch-audit"); err != nil {
		t.Log("arch-audit not installed, so the security marking check is skipped")
		return
	}
	target := net.Pending[0]
	fakeArchAudit(t, []map[string]any{
		avg("AVG-90010", target.Name, "Fixed", "Critical", "arbitrary code execution", target.Available, "CVE-2099-0010"),
	})
	p.audit(ctx)
	local, err = p.LocalCheck(ctx)
	if err != nil {
		t.Fatalf("local check with fake tracker: %v", err)
	}
	if !local.SecurityKnown || len(local.Security) != 1 || local.Security[0].Name != target.Name || local.Security[0].Severity != "critical" {
		t.Errorf("pending %s with a released fix: security=%+v known=%v", target.Name, local.Security, local.SecurityKnown)
	}
}

// TestLiveReboot checks reboot detection against the running kernel.
func TestLiveReboot(t *testing.T) {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatal(err)
	}
	running := strings.TrimSpace(string(data))
	_, statErr := os.Stat(filepath.Join("/usr/lib/modules", running))
	want := statErr != nil

	st := detectReboot(pkgFS{root: "/"}, false)
	t.Logf("running=%s known=%v required=%v reasons=%v", st.Running, st.Known, st.Required, st.Reasons)
	if !st.Known || st.Running != running || st.Required != want {
		t.Errorf("got known=%v running=%q required=%v; want known, %q, required=%v", st.Known, st.Running, st.Required, running, want)
	}
}

// TestLiveLogAndMetadata reads pacman.log and the sync database times.
func TestLiveLogAndMetadata(t *testing.T) {
	p := &pacmanBackend{fs: pkgFS{root: "/"}, runner: execRunner{}}
	last, ok := p.LastUpgrade()
	if !ok {
		t.Error("no upgrade found in /var/log/pacman.log")
	}
	meta, mok := p.MetadataTime()
	if !mok {
		t.Error("no sync databases in /var/lib/pacman/sync")
	}
	t.Logf("last upgrade %v (%s ago); sync databases from %v (%s ago)", last, time.Since(last).Round(time.Minute), meta, time.Since(meta).Round(time.Minute))
}

// TestLiveCollector runs the whole collector once, as GASP does at startup,
// with a temporary state directory.
func TestLiveCollector(t *testing.T) {
	requireArchTools(t, "pacman", "checkupdates", "fakeroot", "arch-audit")
	settings := config.PackagesConfig{}.Resolve()
	c := newPackageCollector(settings, t.TempDir(), pkgFS{root: "/"}, execRunner{}, time.Now)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// What the background goroutine does first, without starting it.
	c.prepare()
	c.refresh(ctx, true)
	c.mu.RLock()
	m := copyPackageMetrics(c.cached)
	c.mu.RUnlock()
	out, _ := json.MarshalIndent(m, "", "  ")
	t.Logf("packages block:\n%s", out)
	if m.UpdateInProgress {
		t.Skip("a package manager is running; try again when it finishes")
	}
	if m.Manager != "pacman" || m.Status != "ok" || m.Method != "checkupdates + arch-audit" {
		t.Errorf("manager=%q status=%q method=%q error=%q", m.Manager, m.Status, m.Method, m.Error)
	}
	if m.SecurityUpdatesPending == nil || m.VulnerableUnfixed == nil || m.LastNetworkCheck == nil || m.RebootRequired == nil {
		t.Errorf("expected security, unfixed, network check and reboot to be known: %+v", m)
	}
}
