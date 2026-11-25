package collectors

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// rebootStatus is what the reboot checks found.
type rebootStatus struct {
	// Known is false when no check could run (nothing to look at).
	Known    bool
	Required bool
	Reasons  []string
	Running  string
}

// detectReboot decides whether the node needs a reboot to finish an
// upgrade. It never runs commands; it only reads files.
//
//  1. /run/reboot-required, written by Debian and Ubuntu packages
//     (update-notifier-common and friends), with the packages that asked in
//     /run/reboot-required.pkgs.
//  2. The running kernel's modules are gone from /usr/lib/modules. This is
//     how an Arch kernel upgrade looks: pacman replaces the kernel in place.
//  3. On distros that keep old kernels (apt), a newer kernel of the same
//     flavour is installed than the one running.
func detectReboot(fs pkgFS, keepsOldKernels bool) rebootStatus {
	st := rebootStatus{}
	if data, err := fs.readFile("/proc/sys/kernel/osrelease"); err == nil {
		st.Running = strings.TrimSpace(string(data))
	}

	if fs.exists("/run/reboot-required") {
		st.Known = true
		st.Required = true
		reason := "/run/reboot-required is present"
		if data, err := fs.readFile("/run/reboot-required.pkgs"); err == nil {
			pkgs := uniqueFields(string(data))
			if len(pkgs) > 0 {
				reason += " (requested by " + strings.Join(pkgs, ", ") + ")"
			}
		}
		st.Reasons = append(st.Reasons, reason)
	} else if fs.exists("/run") {
		// /run exists but the flag does not: on Debian and Ubuntu that is a
		// real "no". On other distros it says nothing, so it does not set
		// Known by itself.
		if fs.exists("/var/lib/dpkg") {
			st.Known = true
		}
	}

	if st.Running == "" {
		return st
	}
	modules := installedKernels(fs)
	if modules == nil {
		return st
	}
	st.Known = true
	if !contains(modules, st.Running) {
		st.Required = true
		st.Reasons = append(st.Reasons, "running kernel "+st.Running+" is no longer installed")
		return st
	}
	if keepsOldKernels {
		if newer := newestSameFlavour(fs, modules, st.Running); newer != "" {
			st.Required = true
			st.Reasons = append(st.Reasons, "newer kernel "+newer+" is installed (running "+st.Running+")")
		}
	}
	return st
}

// installedKernels lists the directories in /usr/lib/modules (or
// /lib/modules). It returns nil when neither can be read or both are empty,
// which happens in containers; then the kernel checks are skipped.
func installedKernels(fs pkgFS) []string {
	for _, dir := range []string{"/usr/lib/modules", "/lib/modules"} {
		entries, err := fs.readDir(dir)
		if err != nil {
			continue
		}
		var names []string
		for _, e := range entries {
			if e.IsDir() {
				names = append(names, e.Name())
			}
		}
		if len(names) > 0 {
			return names
		}
	}
	return nil
}

// newestSameFlavour returns an installed kernel newer than running with the
// same flavour suffix ("-generic", "-amd64", "-cloud-amd64"), or "". Only
// kernels with an image in /boot (or in their modules directory) count, so
// leftover module directories from removed kernels are ignored.
func newestSameFlavour(fs pkgFS, installed []string, running string) string {
	runVer, runFlavour := splitKernelRelease(running)
	if runVer == nil {
		return ""
	}
	type cand struct {
		release string
		ver     []int
	}
	var cands []cand
	for _, rel := range installed {
		if rel == running {
			continue
		}
		ver, flavour := splitKernelRelease(rel)
		if ver == nil || flavour != runFlavour {
			continue
		}
		if !fs.exists("/boot/vmlinuz-"+rel) && !fs.exists(filepath.Join("/usr/lib/modules", rel, "vmlinuz")) {
			continue
		}
		if compareVersions(ver, runVer) > 0 {
			cands = append(cands, cand{rel, ver})
		}
	}
	if len(cands) == 0 {
		return ""
	}
	sort.Slice(cands, func(i, j int) bool { return compareVersions(cands[i].ver, cands[j].ver) > 0 })
	return cands[0].release
}

// kernelRelease splits "6.8.0-49-generic" into numbers [6 8 0 49] and the
// flavour "generic"; "6.1.0-27-cloud-amd64" into [6 1 0 27] and
// "cloud-amd64".
var kernelRelease = regexp.MustCompile(`^(\d+(?:[.-]\d+)*)(?:[-+.~](.*))?$`)

func splitKernelRelease(rel string) ([]int, string) {
	m := kernelRelease.FindStringSubmatch(rel)
	if m == nil {
		return nil, ""
	}
	var ver []int
	for _, part := range strings.FieldsFunc(m[1], func(r rune) bool { return r == '.' || r == '-' }) {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, ""
		}
		ver = append(ver, n)
	}
	return ver, m[2]
}

func compareVersions(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}

func uniqueFields(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range strings.Fields(s) {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
