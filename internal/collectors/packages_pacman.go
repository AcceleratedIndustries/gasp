package collectors

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
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
// arch-audit is installed it runs right after, in the same daily check.
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
	p.audit(ctx)
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
// checkupdates and pacman -Qu. pacman -Qu appends " [ignored]" to packages
// in IgnorePkg/IgnoreGroup; those are skipped, as checkupdates does, so the
// count does not change when GASP falls back to pacman -Qu.
var pacmanUpdateLine = regexp.MustCompile(`^(\S+) (\S+) -> (\S+)(.*)$`)

func parsePacmanUpdates(out []byte) []pendingPackage {
	var pending []pendingPackage
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if m := pacmanUpdateLine.FindStringSubmatch(strings.TrimSpace(sc.Text())); m != nil {
			if strings.Contains(m[4], "[ignored]") {
				continue
			}
			pending = append(pending, pendingPackage{Name: m[1], Installed: m[2], Available: m[3]})
		}
	}
	return pending
}

// archAuditFormat asks arch-audit for one tab-separated line per affected
// package: name, severity ("High risk"), the fixed version (printed only
// when a released fix exists, so empty for "no fix yet" and for fixes that
// are only in the testing repos), CVE ids, and issue types.
const archAuditFormat = "%n\t%s\t%v\t%c\t%t"

// audit runs arch-audit and stores its findings. arch-audit downloads the
// Arch security tracker's issue list, so this runs only in the network
// check.
//
// It asks for archAuditFormat first, since that output is meant for
// machines, and falls back to parsing the human-readable sentences for an
// arch-audit without --format. Output is trusted only when every line
// parses: an unrecognized line means the format changed, and an empty
// result from output GASP cannot read would be a false all-clear. A failed
// audit leaves the previous findings in place.
//
// arch-audit only reads the local database (installed versions); whether a
// fix exists comes from the tracker. So it runs with the system's default
// database path, not checkupdates' private copy.
func (p *pacmanBackend) audit(ctx context.Context) {
	if !p.auditInstalled() {
		return
	}
	type attempt struct {
		args  []string
		parse func([]byte) ([]types.PackageUpdate, []types.PackageUpdate, bool)
	}
	attempts := []attempt{
		{[]string{"--format", archAuditFormat}, parseArchAuditFormat},
		{nil, parseArchAuditText},
	}
	var problems []string
	for _, a := range attempts {
		res, err := p.runner.Run(ctx, nil, "arch-audit", a.args...)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			problems = append(problems, err.Error())
			continue
		}
		if res.ExitCode != 0 {
			problems = append(problems, fmt.Sprintf("exited %d: %s", res.ExitCode, firstLine(res.Stderr)))
			continue
		}
		fixable, unfixed, ok := a.parse(res.Stdout)
		if !ok {
			problems = append(problems, "unrecognized output: "+firstUnparsed(res.Stdout, a.parse))
			continue
		}
		p.lastSecurity, p.lastUnfixed = fixable, unfixed
		p.securityKnown = true
		return
	}
	log.Printf("packages: arch-audit failed, keeping previous findings: %s", strings.Join(problems, "; "))
}

// firstUnparsed returns the first output line the parser rejects, for the
// log.
func firstUnparsed(out []byte, parse func([]byte) ([]types.PackageUpdate, []types.PackageUpdate, bool)) string {
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if _, _, ok := parse([]byte(line)); !ok {
			if len(line) > 120 {
				line = line[:120]
			}
			return line
		}
	}
	return "(none)"
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

// parseArchAuditFormat reads archAuditFormat output. ok is false if any
// non-empty line does not have the expected fields.
func parseArchAuditFormat(out []byte) (fixable, unfixed []types.PackageUpdate, ok bool) {
	fixable = []types.PackageUpdate{}
	unfixed = []types.PackageUpdate{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 5 || f[0] == "" || strings.ContainsAny(f[0], " ") {
			return nil, nil, false
		}
		sev, okSev := archAuditSeverity(f[1])
		if !okSev {
			return nil, nil, false
		}
		u := types.PackageUpdate{Name: f[0], Severity: sev, Available: strings.TrimSpace(f[2])}
		u.Issues = splitList(f[3])
		if len(u.Issues) == 0 {
			u.Issues = splitList(f[4])
		}
		if u.Available != "" {
			fixable = append(fixable, u)
		} else {
			unfixed = append(unfixed, u)
		}
	}
	return fixable, unfixed, true
}

// archAuditText matches arch-audit's human-readable output. Current
// versions print
//
//	openssl is affected by arbitrary code execution. High risk! Update to at least 3.4.1-1!
//	curl is affected by denial of service. (CVE-2026-2222). Medium risk!
//
// (the CVE clause only with -c, "It's required by ..." only with -r, and
// "Update to at least X from the testing repos!" only with --show-testing).
// Older versions started with "Package ", listed CVEs as the issues and said
// "Update to X!". All of these match.
var archAuditText = regexp.MustCompile(`^(?:Package )?(\S+) is affected by (.+?)\. (?:\(([^)]*)\)\. )?(?:It's required by .+?\. )?(\w+) risk!(?: Update to (?:at least )?(\S+?)( from (?:the )?testing repos)?!)?$`)

// parseArchAuditText reads arch-audit's default output. A fix that is only
// in the testing repos counts as no fix yet: pacman -Syu on a normal system
// cannot get it. ok is false if any non-empty line does not match.
func parseArchAuditText(out []byte) (fixable, unfixed []types.PackageUpdate, ok bool) {
	fixable = []types.PackageUpdate{}
	unfixed = []types.PackageUpdate{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		m := archAuditText.FindStringSubmatch(line)
		if m == nil {
			return nil, nil, false
		}
		sev, _ := archAuditSeverity(m[4] + " risk")
		u := types.PackageUpdate{Name: m[1], Severity: sev}
		if u.Issues = splitList(m[3]); len(u.Issues) == 0 {
			u.Issues = splitList(m[2])
		}
		if m[5] != "" && m[6] == "" {
			u.Available = m[5]
			fixable = append(fixable, u)
		} else {
			unfixed = append(unfixed, u)
		}
	}
	return fixable, unfixed, true
}

// archAuditSeverity turns "High risk" into "high". ok is false for text
// that is not a severity.
func archAuditSeverity(s string) (string, bool) {
	word, found := strings.CutSuffix(strings.TrimSpace(s), " risk")
	if !found {
		return "", false
	}
	word = strings.ToLower(word)
	if _, known := severityRank[word]; !known {
		return "", false
	}
	return word, true
}

func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
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
