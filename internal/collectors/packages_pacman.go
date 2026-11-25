package collectors

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/accelerated-industries/gasp/internal/types"
)

// pacmanBackend checks Arch Linux and derivatives.
//
// The network check runs checkupdates, which syncs a private copy of the
// sync databases (CHECKUPDATES_DB) and never touches /var/lib/pacman/sync,
// so it is safe as a normal user and cannot cause a partial upgrade. When
// arch-audit is installed it runs against that same private copy.
//
// Between network checks, the local check compares installed packages with
// whatever the system's own sync databases hold.
type pacmanBackend struct {
	fs     pkgFS
	runner cmdRunner
	// dbDir is checkupdates' private database copy, under GASP's state dir.
	// Empty means no private copy (no state dir), so the network check
	// lets checkupdates use its default temp location.
	dbDir string

	// lastSecurity is the arch-audit result from the last network check,
	// reused by local checks so a security finding does not vanish between
	// daily runs. It is only read and written by the collector's single
	// refresh goroutine.
	lastSecurity   []types.PackageUpdate
	lastUnfixed    []types.PackageUpdate
	securityKnown  bool
	hasAudit       bool
	auditLookedFor bool
}

func (p *pacmanBackend) Name() string { return "pacman" }

// KeepsOldKernels is false: pacman replaces the kernel in place, so the
// missing-modules check covers it.
func (p *pacmanBackend) KeepsOldKernels() bool { return false }

func (p *pacmanBackend) env() []string {
	if p.dbDir == "" {
		return nil
	}
	return []string{"CHECKUPDATES_DB=" + p.dbDir}
}

func (p *pacmanBackend) auditInstalled() bool {
	if !p.auditLookedFor {
		_, err := p.runner.LookPath("arch-audit")
		p.hasAudit = err == nil
		p.auditLookedFor = true
	}
	return p.hasAudit
}

// NetworkCheck syncs the private database copy and lists pending updates,
// then runs arch-audit.
func (p *pacmanBackend) NetworkCheck(ctx context.Context) (checkResult, error) {
	if _, err := p.runner.LookPath("checkupdates"); err != nil {
		return checkResult{}, errNoNetworkCheck
	}
	if p.dbDir != "" {
		if err := os.MkdirAll(p.dbDir, 0o700); err != nil {
			return checkResult{}, fmt.Errorf("create %s: %w", p.dbDir, err)
		}
	}
	res, err := p.runner.Run(ctx, p.env(), "checkupdates")
	if err != nil {
		return checkResult{}, fmt.Errorf("checkupdates: %w", err)
	}
	pending, err := checkupdatesResult(res)
	if err != nil {
		return checkResult{}, err
	}
	out := checkResult{Method: "checkupdates", Pending: pending}
	p.audit(ctx, true)
	p.applySecurity(&out)
	return out, nil
}

// LocalCheck lists pending updates from the databases already on disk.
// It prefers checkupdates --nosync on the private copy (fresher, since the
// daily network check updates it) and falls back to pacman -Qu.
func (p *pacmanBackend) LocalCheck(ctx context.Context) (checkResult, error) {
	// dbDir is a real path in GASP's state dir, not under the system root.
	if p.dbDir != "" && dirExists(filepath.Join(p.dbDir, "sync")) {
		if _, err := p.runner.LookPath("checkupdates"); err == nil {
			res, err := p.runner.Run(ctx, p.env(), "checkupdates", "--nosync")
			if err == nil {
				if pending, perr := checkupdatesResult(res); perr == nil {
					out := checkResult{Method: "checkupdates --nosync", Pending: pending}
					p.applySecurity(&out)
					return out, nil
				}
			} else if ctx.Err() != nil {
				return checkResult{}, fmt.Errorf("checkupdates --nosync: %w", err)
			}
		}
	}

	res, err := p.runner.Run(ctx, nil, "pacman", "-Qu")
	if err != nil {
		return checkResult{}, fmt.Errorf("pacman -Qu: %w", err)
	}
	// pacman -Qu exits 1 with no output when nothing is out of date.
	if res.ExitCode != 0 && !(res.ExitCode == 1 && len(bytes.TrimSpace(res.Stdout)) == 0) {
		return checkResult{}, fmt.Errorf("pacman -Qu exited %d: %s", res.ExitCode, firstLine(res.Stderr))
	}
	out := checkResult{Method: "pacman -Qu", Pending: parsePacmanUpdates(res.Stdout)}
	// arch-audit downloads the security tracker, so it only runs in the
	// network check. Its last findings still apply here.
	p.applySecurity(&out)
	return out, nil
}

// checkupdatesResult interprets checkupdates' exit status: 0 means updates,
// 2 means none, anything else is an error.
func checkupdatesResult(res cmdResult) ([]pendingPackage, error) {
	switch res.ExitCode {
	case 0:
		return parsePacmanUpdates(res.Stdout), nil
	case 2:
		return nil, nil
	default:
		msg := firstLine(res.Stderr)
		if msg == "" {
			msg = firstLine(res.Stdout)
		}
		return nil, fmt.Errorf("checkupdates exited %d: %s", res.ExitCode, msg)
	}
}

// pacmanUpdateLine matches "name old -> new", the format of both
// checkupdates and pacman -Qu. pacman may append " [ignored]".
var pacmanUpdateLine = regexp.MustCompile(`^(\S+) (\S+) -> (\S+)`)

func parsePacmanUpdates(out []byte) []pendingPackage {
	var pending []pendingPackage
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if m := pacmanUpdateLine.FindStringSubmatch(strings.TrimSpace(sc.Text())); m != nil {
			pending = append(pending, pendingPackage{Name: m[1], Installed: m[2], Available: m[3]})
		}
	}
	return pending
}

// audit runs arch-audit and stores its findings. arch-audit downloads the
// Arch security tracker's issue list, so this runs only in the network
// check. useDB points it at the private database copy; if that run fails it
// retries with the defaults. A failed audit leaves the previous findings in
// place.
func (p *pacmanBackend) audit(ctx context.Context, useDB bool) {
	if !p.auditInstalled() {
		return
	}
	var attempts [][]string
	if useDB && p.dbDir != "" {
		attempts = append(attempts, []string{"--dbpath", p.dbDir})
	}
	attempts = append(attempts, nil)
	for _, args := range attempts {
		res, err := p.runner.Run(ctx, nil, "arch-audit", args...)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		fixable, unfixed := parseArchAudit(res.Stdout)
		// Trust a non-zero exit only if it still printed findings.
		if res.ExitCode != 0 && len(fixable)+len(unfixed) == 0 {
			continue
		}
		p.lastSecurity, p.lastUnfixed = fixable, unfixed
		p.securityKnown = true
		return
	}
}

// auditState is arch-audit's last findings, kept in the state file so a
// restart does not forget them until the next daily network check.
type auditState struct {
	Fixable []types.PackageUpdate `json:"fixable"`
	Unfixed []types.PackageUpdate `json:"unfixed"`
}

func (p *pacmanBackend) saveAudit() *auditState {
	if !p.securityKnown {
		return nil
	}
	return &auditState{Fixable: p.lastSecurity, Unfixed: p.lastUnfixed}
}

func (p *pacmanBackend) restoreAudit(a *auditState) {
	if a == nil || p.securityKnown {
		return
	}
	p.lastSecurity, p.lastUnfixed = a.Fixable, a.Unfixed
	p.securityKnown = true
}

// applySecurity marks pending packages that fix a known security issue.
// Fixed findings count only while the package is still pending, so a
// finding goes away as soon as the package is upgraded.
func (p *pacmanBackend) applySecurity(out *checkResult) {
	if !p.securityKnown {
		return
	}
	out.SecurityKnown = true
	byName := map[string]types.PackageUpdate{}
	for _, s := range p.lastSecurity {
		byName[s.Name] = s
	}
	for i := range out.Pending {
		pend := &out.Pending[i]
		s, ok := byName[pend.Name]
		if !ok {
			continue
		}
		pend.Security = true
		s.Installed = pend.Installed
		s.Available = pend.Available
		out.Security = append(out.Security, s)
	}
	out.Unfixed = append([]types.PackageUpdate{}, p.lastUnfixed...)
	out.Method += " + arch-audit"
}

// archAuditLine matches arch-audit's default output, for example:
//
//	Package openssl is affected by CVE-2026-1234, CVE-2026-1235. High risk!
//	Package curl is affected by CVE-2026-2222. Medium risk! Update to 8.11.1-1!
//	Package foo is affected by CVE-2026-3333. Low risk! Update to 1.2-1 from testing repos!
var archAuditLine = regexp.MustCompile(`^Package (\S+) is affected by (.+?)\. (\w+) risk!(?: Update to (\S+?)( from testing repos)?!)?`)

// parseArchAudit splits arch-audit output into packages a released update
// fixes and packages with no fix yet. A fix that is only in the testing
// repos counts as no fix yet: pacman -Syu on a normal system cannot get it.
func parseArchAudit(out []byte) (fixable, unfixed []types.PackageUpdate) {
	fixable = []types.PackageUpdate{}
	unfixed = []types.PackageUpdate{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		m := archAuditLine.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue
		}
		var issues []string
		for _, issue := range strings.Split(m[2], ",") {
			if issue = strings.TrimSpace(issue); issue != "" {
				issues = append(issues, issue)
			}
		}
		u := types.PackageUpdate{Name: m[1], Severity: strings.ToLower(m[3]), Issues: issues}
		u.Available = m[4]
		if m[4] != "" && m[5] == "" {
			fixable = append(fixable, u)
		} else {
			unfixed = append(unfixed, u)
		}
	}
	return fixable, unfixed
}

// MetadataTime is the newest sync database on the system. The private
// checkupdates copy is not counted: it says nothing about what pacman -Syu
// would install.
func (p *pacmanBackend) MetadataTime() (time.Time, bool) {
	entries, err := p.fs.readDir("/var/lib/pacman/sync")
	if err != nil {
		return time.Time{}, false
	}
	var newest time.Time
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		if info, err := e.Info(); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest, !newest.IsZero()
}

func (p *pacmanBackend) StateStamp() string {
	paths := []string{"/var/lib/pacman/local", "/var/log/pacman.log"}
	if entries, err := p.fs.readDir("/var/lib/pacman/sync"); err == nil {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".db") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			paths = append(paths, "/var/lib/pacman/sync/"+n)
		}
	}
	return mtimeStamp(p.fs, paths...)
}

// LastUpgrade reads the last "[ALPM] upgraded" line in pacman.log.
func (p *pacmanBackend) LastUpgrade() (time.Time, bool) {
	data, err := p.fs.readTail("/var/log/pacman.log", 4<<20)
	if err != nil {
		return time.Time{}, false
	}
	return parsePacmanLog(data, time.Local)
}

// pacmanLogUpgrade matches an upgrade in pacman.log, in both the current
// format ("[2026-11-20T08:14:03+0000] [ALPM] upgraded ...") and the old
// one ("[2019-03-01 10:22] [ALPM] upgraded ...").
var pacmanLogUpgrade = regexp.MustCompile(`^\[([^\]]+)\] \[ALPM\] upgraded `)

func parsePacmanLog(data []byte, loc *time.Location) (time.Time, bool) {
	lines := strings.Split(string(data), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		m := pacmanLogUpgrade.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		for _, layout := range []string{"2006-01-02T15:04:05-0700", "2006-01-02T15:04:05Z07:00"} {
			if t, err := time.Parse(layout, m[1]); err == nil {
				return t, true
			}
		}
		if t, err := time.ParseInLocation("2006-01-02 15:04", m[1], loc); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}
