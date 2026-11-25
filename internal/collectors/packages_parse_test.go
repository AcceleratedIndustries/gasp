package collectors

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/accelerated-industries/gasp/internal/types"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "packages", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseAptSimulation(t *testing.T) {
	pending := parseAptSimulation(readFixture(t, "apt-ubuntu-2404.txt"))
	if len(pending) != 32 {
		t.Fatalf("pending = %d, want 32", len(pending))
	}
	security := 0
	byName := map[string]pendingPackage{}
	for _, p := range pending {
		byName[p.Name] = p
		if p.Security {
			security++
		}
	}
	if security != 20 {
		t.Errorf("security = %d, want 20", security)
	}
	ssh, ok := byName["libssh-4"]
	if !ok || !ssh.Security || ssh.Installed != "0.10.6-2ubuntu0.5" || ssh.Available != "0.10.6-2ubuntu0.6" {
		t.Errorf("libssh-4 = %+v", ssh)
	}
	if p, ok := byName["docker-ce"]; !ok || p.Security {
		t.Errorf("docker-ce should be a routine update: %+v", p)
	}
}

func TestParseAptSimulationEdgeCases(t *testing.T) {
	out := []byte(`Inst newpkg (1.0 Debian:12/stable [amd64])
Inst openssl [3.0.14-1~deb12u1] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])
Inst libfoo [1.0-1] (1.0-2 Debian:12.8/stable, Debian-Security:12/stable-security [amd64]) []
Inst bar [2.0] (2.1 Debian:12/stable-updates [amd64])
Conf openssl (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])
`)
	pending := parseAptSimulation(out)
	if len(pending) != 3 {
		t.Fatalf("pending = %+v, want 3 upgrades (new install skipped)", pending)
	}
	want := map[string]bool{"openssl": true, "libfoo": true, "bar": false}
	for _, p := range pending {
		if p.Security != want[p.Name] {
			t.Errorf("%s security = %v, want %v", p.Name, p.Security, want[p.Name])
		}
	}
}

func TestParseAptHistory(t *testing.T) {
	got, ok := parseAptHistory(readFixture(t, "apt-history.log"), time.UTC)
	want := time.Date(2026, 11, 18, 14, 2, 40, 0, time.UTC)
	if !ok || !got.Equal(want) {
		t.Errorf("last upgrade = %v %v, want %v (the later Install-only entry must not count)", got, ok, want)
	}
	if _, ok := parseAptHistory([]byte("Start-Date: 2026-11-21  03:34:28\nInstall: x (1)\nEnd-Date: 2026-11-21  03:34:28\n"), time.UTC); ok {
		t.Error("an install-only log should report no upgrade")
	}
}

func TestParsePacmanUpdates(t *testing.T) {
	pending, ignored := parsePacmanUpdates(readFixture(t, "pacman-qu.txt"))
	// vim is in IgnorePkg: listed apart, not as pending.
	if len(pending) != 2 || pending[1].Name != "openssl" {
		t.Fatalf("pending = %+v", pending)
	}
	if len(ignored) != 1 || ignored[0].Name != "vim" || ignored[0].Available != "9.1.0900-1" {
		t.Errorf("ignored = %+v", ignored)
	}
	if pending[0].Installed != "6.12.4.arch1-1" {
		t.Errorf("linux installed = %q", pending[0].Installed)
	}
}

func TestCheckupdatesResult(t *testing.T) {
	if p, err := checkupdatesResult(cmdResult{Stdout: readFixture(t, "checkupdates.txt")}); err != nil || len(p) != 4 {
		t.Errorf("exit 0: %v, %d pending", err, len(p))
	}
	if p, err := checkupdatesResult(cmdResult{ExitCode: 2}); err != nil || len(p) != 0 {
		t.Errorf("exit 2 should mean no updates: %v %v", p, err)
	}
	if _, err := checkupdatesResult(cmdResult{ExitCode: 1, Stderr: []byte("==> ERROR: Cannot fetch updates\n")}); err == nil {
		t.Error("exit 1 should be an error")
	}
}

// The arch-audit fixtures follow the output code in arch-audit's source
// (print_affected_colored and print_affected_formatted in src/main.rs,
// v0.1.20). Replace them with output captured on a real Arch machine; the
// archlive tests print it.

func TestParseArchAuditFormat(t *testing.T) {
	fixable, unfixed, ok := parseArchAuditFormat(readFixture(t, "arch-audit-format.txt"))
	if !ok || len(fixable) != 2 || len(unfixed) != 2 {
		t.Fatalf("ok=%v\nfixable = %+v\nunfixed = %+v", ok, fixable, unfixed)
	}
	if fixable[0].Name != "glibc" || fixable[0].Severity != "critical" || fixable[0].Available != "2.40-2" {
		t.Errorf("glibc = %+v", fixable[0])
	}
	if o := fixable[1]; o.Name != "openssl" || o.Severity != "high" || o.Available != "3.4.1-1" || len(o.Issues) != 2 || o.Issues[1] != "CVE-2026-1235" {
		t.Errorf("openssl = %+v", o)
	}
	if unfixed[0].Name != "curl" || unfixed[0].Available != "" || unfixed[1].Name != "libxml2" || unfixed[1].Severity != "low" {
		t.Errorf("unfixed = %+v", unfixed)
	}
}

func TestParseArchAuditFormatEdgeCases(t *testing.T) {
	if f, u, ok := parseArchAuditFormat(nil); !ok || len(f)+len(u) != 0 || f == nil || u == nil {
		t.Errorf("empty output should be a clean result with empty lists: %v %v %v", f, u, ok)
	}
	// No CVEs: the issue types stand in.
	f, _, ok := parseArchAuditFormat([]byte("zlib\tUnknown risk\t1.3-2\t\tdenial of service\n"))
	if !ok || len(f) != 1 || f[0].Severity != "unknown" || f[0].Issues[0] != "denial of service" {
		t.Errorf("zlib = %+v ok=%v", f, ok)
	}
	for _, bad := range []string{
		"openssl is affected by arbitrary code execution. High risk!", // sentence output
		"openssl\tHigh risk\t3.4.1-1",                                 // too few fields
		"openssl\tHigh\t3.4.1-1\t\t",                                  // severity without "risk"
		"openssl\tSevere risk\t3.4.1-1\t\t",                           // unknown severity
	} {
		if _, _, ok := parseArchAuditFormat([]byte("glibc\tCritical risk\t2.40-2\t\t\n" + bad + "\n")); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestParseArchAuditText(t *testing.T) {
	fixable, unfixed, ok := parseArchAuditText(readFixture(t, "arch-audit.txt"))
	if !ok || len(fixable) != 2 || len(unfixed) != 2 {
		t.Fatalf("ok=%v\nfixable = %+v\nunfixed = %+v", ok, fixable, unfixed)
	}
	if o := fixable[1]; o.Name != "openssl" || o.Severity != "high" || o.Available != "3.4.1-1" || len(o.Issues) != 2 || o.Issues[0] != "arbitrary code execution" {
		t.Errorf("openssl = %+v", o)
	}
	if fixable[0].Name != "glibc" || fixable[0].Severity != "critical" || fixable[0].Available != "2.40-2" {
		t.Errorf("glibc = %+v", fixable[0])
	}
	if unfixed[0].Name != "curl" || unfixed[1].Name != "libxml2" {
		t.Errorf("unfixed = %+v", unfixed)
	}
}

func TestParseArchAuditTextVariants(t *testing.T) {
	cases := []struct {
		line     string
		name     string
		fixed    string // "" means unfixed
		severity string
		issue0   string
	}{
		// Old arch-audit: "Package " prefix, CVEs as issues, "Update to X!".
		{"Package openssl is affected by CVE-2017-3735, CVE-2017-3736. Medium risk! Update to 1.1.0g-1!", "openssl", "1.1.0g-1", "medium", "CVE-2017-3735"},
		{"Package jasper is affected by CVE-2016-8886. Medium risk!", "jasper", "", "medium", "CVE-2016-8886"},
		// -c adds the CVE clause; the CVEs become the issues.
		{"curl is affected by denial of service. (CVE-2026-2222, CVE-2026-2223). Medium risk! Update to at least 8.11.1-1!", "curl", "8.11.1-1", "medium", "CVE-2026-2222"},
		// --show-testing: a testing-only fix is not a fix for a normal system.
		{"curl is affected by denial of service. Medium risk! Update to at least 8.11.1-1 from the testing repos!", "curl", "", "medium", "denial of service"},
		// -r adds the required-by clause.
		{"libpng is affected by arbitrary code execution. It's required by gtk3, qt6-base. High risk! Update to at least 1.6.44-1!", "libpng", "1.6.44-1", "high", "arbitrary code execution"},
		{"foo is affected by unknown. Unknown risk!", "foo", "", "unknown", "unknown"},
		{"bar is affected by privilege escalation. Critical risk! Update to at least 1:2.3-4!", "bar", "1:2.3-4", "critical", "privilege escalation"},
	}
	for _, c := range cases {
		fixable, unfixed, ok := parseArchAuditText([]byte(c.line + "\n"))
		if !ok || len(fixable)+len(unfixed) != 1 {
			t.Errorf("%q: ok=%v fixable=%+v unfixed=%+v", c.line, ok, fixable, unfixed)
			continue
		}
		var u types.PackageUpdate
		if c.fixed != "" {
			if len(fixable) != 1 {
				t.Errorf("%q: want fixable, got unfixed %+v", c.line, unfixed)
				continue
			}
			u = fixable[0]
		} else {
			if len(unfixed) != 1 {
				t.Errorf("%q: want unfixed, got fixable %+v", c.line, fixable)
				continue
			}
			u = unfixed[0]
		}
		if u.Name != c.name || u.Available != c.fixed || u.Severity != c.severity || len(u.Issues) == 0 || u.Issues[0] != c.issue0 {
			t.Errorf("%q: got %+v", c.line, u)
		}
	}
	if _, _, ok := parseArchAuditText([]byte("openssl is affected by arbitrary code execution. High risk!\nwarning: something new\n")); ok {
		t.Error("an unrecognized line must make the whole result untrusted")
	}
	if f, u, ok := parseArchAuditText([]byte("\n")); !ok || len(f)+len(u) != 0 {
		t.Error("empty output should be a clean result")
	}
}

func TestParsePacmanLog(t *testing.T) {
	got, ok := parsePacmanLog(readFixture(t, "pacman.log"), time.UTC)
	want := time.Date(2026, 11, 14, 9, 12, 59, 0, time.UTC)
	if !ok || !got.Equal(want) {
		t.Errorf("last upgrade = %v %v, want %v", got, ok, want)
	}
	old := []byte("[2019-03-01 10:22] [ALPM] upgraded bash (5.0.0-1 -> 5.0.002-1)\n")
	got, ok = parsePacmanLog(old, time.UTC)
	if !ok || !got.Equal(time.Date(2019, 3, 1, 10, 22, 0, 0, time.UTC)) {
		t.Errorf("old format = %v %v", got, ok)
	}
	if _, ok := parsePacmanLog([]byte("[2026-11-15T10:00:00+0000] [ALPM] installed htop (3.3.0-3)\n"), time.UTC); ok {
		t.Error("installs are not upgrades")
	}
}

func TestParseOSRelease(t *testing.T) {
	id, like := parseOSRelease([]byte("NAME=\"EndeavourOS\"\nID=endeavouros\nID_LIKE=arch\n"))
	if id != "endeavouros" || len(like) != 1 || like[0] != "arch" {
		t.Errorf("got %q %v", id, like)
	}
	id, like = parseOSRelease([]byte("ID=ubuntu\nID_LIKE=\"debian\"\n"))
	if id != "ubuntu" || like[0] != "debian" {
		t.Errorf("got %q %v", id, like)
	}
}

func TestSplitKernelRelease(t *testing.T) {
	cases := []struct {
		rel     string
		flavour string
	}{
		{"6.8.0-49-generic", "generic"},
		{"6.1.0-27-cloud-amd64", "cloud-amd64"},
		{"6.12.8-arch1-1", "arch1-1"},
	}
	for _, c := range cases {
		ver, flavour := splitKernelRelease(c.rel)
		if ver == nil || flavour != c.flavour {
			t.Errorf("%s: %v %q, want flavour %q", c.rel, ver, flavour, c.flavour)
		}
	}
	a, _ := splitKernelRelease("6.8.0-51-generic")
	b, _ := splitKernelRelease("6.8.0-49-generic")
	if compareVersions(a, b) <= 0 {
		t.Error("6.8.0-51 should be newer than 6.8.0-49")
	}
}
