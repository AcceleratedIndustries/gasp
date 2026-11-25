package collectors

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/accelerated-industries/gasp/internal/types"
)

// pendingPackage is one package with a newer version available.
type pendingPackage struct {
	Name      string
	Installed string
	Available string
	Security  bool
}

// checkResult is what one backend check found.
type checkResult struct {
	Method  string
	Pending []pendingPackage

	// SecurityKnown is false when this check cannot tell security updates
	// from routine ones (for example pacman without arch-audit).
	SecurityKnown bool
	// Security lists packages with a known security issue that an
	// available update fixes.
	Security []types.PackageUpdate
	// Unfixed lists vulnerable packages with no fix released yet. Only
	// arch-audit reports these; nil means unknown.
	Unfixed []types.PackageUpdate
}

// pkgBackend is one package manager.
type pkgBackend interface {
	Name() string
	// LocalCheck reads only cached metadata. It never uses the network.
	LocalCheck(ctx context.Context) (checkResult, error)
	// NetworkCheck refreshes a private copy of the metadata and checks
	// against it. Backends without one return errNoNetworkCheck.
	NetworkCheck(ctx context.Context) (checkResult, error)
	// MetadataTime is when the package metadata was last refreshed.
	MetadataTime() (time.Time, bool)
	// StateStamp changes whenever metadata or installed packages change.
	StateStamp() string
	// LastUpgrade is when packages were last upgraded.
	LastUpgrade() (time.Time, bool)
	// KeepsOldKernels is true when old kernels stay installed after an
	// upgrade, so a newer installed kernel means a reboot is due.
	KeepsOldKernels() bool
}

var errNoNetworkCheck = fmt.Errorf("no network check for this package manager")

// mtimeStamp joins the modification times of paths that exist.
func mtimeStamp(fs pkgFS, paths ...string) string {
	var b strings.Builder
	for _, p := range paths {
		if info, err := fs.stat(p); err == nil {
			fmt.Fprintf(&b, "%s=%d;", p, info.ModTime().UnixNano())
		}
	}
	return b.String()
}

// ---- apt ----

type aptBackend struct {
	fs     pkgFS
	runner cmdRunner
}

func (a *aptBackend) Name() string { return "apt" }

func (a *aptBackend) KeepsOldKernels() bool { return true }

func (a *aptBackend) NetworkCheck(context.Context) (checkResult, error) {
	return checkResult{}, errNoNetworkCheck
}

// LocalCheck simulates a full upgrade. apt-get -s works as any user, takes
// no lock and changes nothing.
func (a *aptBackend) LocalCheck(ctx context.Context) (checkResult, error) {
	// Dir::Log::Planner=/dev/null stops apt from writing its planner log
	// (/var/log/apt/eipp.log.xz) when GASP happens to run as root.
	res, err := a.runner.Run(ctx, nil, "apt-get", "-s", "-q", "-o", "Dir::Log::Planner=/dev/null", "dist-upgrade")
	if err != nil {
		return checkResult{}, fmt.Errorf("apt-get -s dist-upgrade: %w", err)
	}
	if res.ExitCode != 0 {
		return checkResult{}, fmt.Errorf("apt-get -s dist-upgrade exited %d: %s", res.ExitCode, firstLine(res.Stderr))
	}
	pending := parseAptSimulation(res.Stdout)
	out := checkResult{Method: "apt-get -s dist-upgrade", Pending: pending, SecurityKnown: true}
	for _, p := range pending {
		if p.Security {
			out.Security = append(out.Security, types.PackageUpdate{Name: p.Name, Installed: p.Installed, Available: p.Available})
		}
	}
	return out, nil
}

// aptInstLine matches an upgrade in apt-get -s output:
//
//	Inst libssh-4 [0.10.6-2ubuntu0.5] (0.10.6-2ubuntu0.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
//
// Lines without the [installed] part are new installs, not upgrades.
var aptInstLine = regexp.MustCompile(`^Inst (\S+) \[([^\]]*)\] \((\S+) (.*) \[[^\]]*\]\)`)

// parseAptSimulation returns the upgrades in apt-get -s output. An upgrade
// is a security update when any of its origins is a -security suite
// (Debian "bookworm-security", Ubuntu "noble-security"). apt lists every
// origin, so a fix published to both -updates and -security still counts.
func parseAptSimulation(out []byte) []pendingPackage {
	var pending []pendingPackage
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		m := aptInstLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		p := pendingPackage{Name: m[1], Installed: m[2], Available: m[3]}
		for _, origin := range strings.Split(m[4], ",") {
			if strings.HasSuffix(strings.TrimSpace(origin), "-security") {
				p.Security = true
				break
			}
		}
		pending = append(pending, p)
	}
	return pending
}

// MetadataTime prefers the stamp apt-daily writes after a successful update,
// then the package cache, then the lists directory itself. The files inside
// the lists directory keep the mirror's timestamps, so they are not used.
func (a *aptBackend) MetadataTime() (time.Time, bool) {
	for _, p := range []string{
		"/var/lib/apt/periodic/update-success-stamp",
		"/var/cache/apt/pkgcache.bin",
		"/var/lib/apt/lists",
	} {
		if info, err := a.fs.stat(p); err == nil {
			return info.ModTime(), true
		}
	}
	return time.Time{}, false
}

func (a *aptBackend) StateStamp() string {
	return mtimeStamp(a.fs,
		"/var/lib/apt/periodic/update-success-stamp",
		"/var/cache/apt/pkgcache.bin",
		"/var/lib/apt/lists",
		"/var/lib/dpkg/status",
	)
}

// LastUpgrade reads the End-Date of the last upgrade in apt's history log,
// then in last month's rotated log. With no log at all it falls back to the
// dpkg status file's mtime. A log with no upgrade in it means "unknown".
func (a *aptBackend) LastUpgrade() (time.Time, bool) {
	data, err := a.fs.readTail("/var/log/apt/history.log", 4<<20)
	if err != nil {
		if info, serr := a.fs.stat("/var/lib/dpkg/status"); serr == nil {
			return info.ModTime(), true
		}
		return time.Time{}, false
	}
	if t, ok := parseAptHistory(data, time.Local); ok {
		return t, true
	}
	if old, err := a.fs.readGzip("/var/log/apt/history.log.1.gz", 16<<20); err == nil {
		if t, ok := parseAptHistory(old, time.Local); ok {
			return t, true
		}
	}
	return time.Time{}, false
}

// parseAptHistory returns the End-Date of the last history entry that
// upgraded packages.
func parseAptHistory(data []byte, loc *time.Location) (time.Time, bool) {
	var last time.Time
	found := false
	upgraded := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Start-Date:"):
			upgraded = false
		case strings.HasPrefix(line, "Upgrade:"):
			upgraded = true
		case strings.HasPrefix(line, "End-Date:") && upgraded:
			// "End-Date: 2026-11-21  03:34:28"
			value := strings.Join(strings.Fields(strings.TrimPrefix(line, "End-Date:")), " ")
			if t, err := time.ParseInLocation("2006-01-02 15:04:05", value, loc); err == nil {
				last, found = t, true
			}
		}
	}
	return last, found
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
