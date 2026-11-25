package collectors

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
	pending := parsePacmanUpdates(readFixture(t, "pacman-qu.txt"))
	if len(pending) != 3 {
		t.Fatalf("pending = %+v", pending)
	}
	if pending[2].Name != "vim" || pending[2].Available != "9.1.0900-1" {
		t.Errorf("ignored package parsed as %+v", pending[2])
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

func TestParseArchAudit(t *testing.T) {
	fixable, unfixed := parseArchAudit(readFixture(t, "arch-audit.txt"))
	if len(fixable) != 2 || len(unfixed) != 2 {
		t.Fatalf("fixable = %+v\nunfixed = %+v", fixable, unfixed)
	}
	if fixable[0].Name != "openssl" || fixable[0].Severity != "high" || fixable[0].Available != "3.4.1-1" || len(fixable[0].Issues) != 2 {
		t.Errorf("openssl = %+v", fixable[0])
	}
	if fixable[1].Name != "glibc" || fixable[1].Severity != "critical" {
		t.Errorf("glibc = %+v", fixable[1])
	}
	// A fix only in testing is not a fix a normal system can install.
	names := map[string]bool{}
	for _, u := range unfixed {
		names[u.Name] = true
	}
	if !names["curl"] || !names["libxml2"] {
		t.Errorf("unfixed = %+v, want curl (testing only) and libxml2", unfixed)
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
