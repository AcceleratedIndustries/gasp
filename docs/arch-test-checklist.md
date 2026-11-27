# GASP package reporting: Arch test checklist

For the Arch mini PC coming back online. Run it against branch `fix/arch-audit-parser` (3 commits on main f015398), which fixes the arch-audit mismatches below and adds live tests (step 4). Not merged; no PR yet. Run GASP as your normal user, not root. Everything goes in `~/gasp-test/`; save each command's output under `~/gasp-test/out/` so the results can be read back afterwards.

**On phunklab:** the repo is already checked out at `~/dev/gasp`. In step 4, use it in place of the clone:

```
cd ~/dev/gasp && git fetch origin && git checkout fix/arch-audit-parser && git pull
```

Outputs still go under `~/gasp-test/out/`, and the binary is still built to `~/gasp-test/gasp`. Before step 2, make the folders and the minimal config that step 1 would have made:

```
mkdir -p ~/gasp-test/out
printf 'collection:\n  packages:\n    network_jitter: 0s\n' > ~/gasp-test/config.yaml
```

Step 1 (the pre-upgrade snapshot) only applies if the box hasn't been upgraded yet. Skip it if `pacman -Syu` has already run since the box came back online.

Code under test: `internal/collectors/packages_pacman.go` (checkupdates, pacman -Qu, arch-audit), `packages_reboot.go` (reboot), `packages.go` (schedule, state file, roll-up). State lives in `~/.local/state/gasp/` (`packages-state.json`, and checkupdates' private DB copy in `checkup-db/`).

## 0. Mismatches found by reading the code

Status: A, B, C, D, E and G are fixed on `fix/arch-audit-parser`. F is documented in the README (install fakeroot).

Checked against arch-audit's source (0.1.20, the last GitHub release) and pacman-contrib's current checkupdates. Arch now packages arch-audit from its own GitLab, which I couldn't reach, so step 3 captures the real version and output to confirm.

| # | What | Where | Effect |
|---|------|-------|--------|
| A | arch-audit prints `openssl is affected by ...`, with no `Package ` prefix. The regex requires `^Package `. | `archAuditLine` in packages_pacman.go | Every line fails to match. arch-audit exits 0, so GASP accepts an empty result: `security_updates_pending: 0` and "none of them security" on a vulnerable box. A silent false all-clear. Confirmed with a scratch test against lines in the real format. |
| B | The fix text is `Update to at least 3.4.1-1!`, not `Update to 3.4.1-1!`. | same regex, group 4 | Even with A fixed, no fix version is captured, so every finding lands in `vulnerable_unfixed` and none counts as a pending security update. |
| C | Testing-only fixes print `from the testing repos!` and only with `--show-testing`, which GASP doesn't pass. | same regex, group 5 | Harmless: without the flag those lines have no "Update to", so they already count as unfixed (the decided behaviour). The ` from testing repos` branch is dead code. |
| D | The issues text is the issue type ("arbitrary code execution, denial of service"), not CVE ids. CVEs only appear with `-c`, in an extra `(CVE-..., ...). ` clause. | `Issues` field, types.go comment | `issues` in /metrics holds types, not CVE/AVG ids as documented. |
| E | `arch-audit --dbpath <checkup-db>` reads installed packages from `<checkup-db>/local`, a symlink checkupdates creates. If it's missing, arch-audit sees nothing installed and exits 0 with no output. | `audit()` | GASP only retries without `--dbpath` on an error or a non-zero exit, so this would also read as "no security issues". Check the symlink in step 6. |
| F | checkupdates dies with "Cannot find the fakeroot binary" if fakeroot is missing, and the check runs before the `--nosync` check too. | NetworkCheck / LocalCheck | Without fakeroot the network check fails every time and the local check falls back to `pacman -Qu`. Install fakeroot (step 2). |
| G | `pacman -Qu` lists IgnorePkg packages with `[ignored]` and GASP counts them. checkupdates filters them out. | `parsePacmanUpdates` | `updates_pending` can jump by the ignored count when GASP falls back to `pacman -Qu`. Minor. Now counted apart as `updates_ignored` (Will's call, Nov 25). |

The fix on the branch: GASP now runs `arch-audit --format "%n\t%s\t%v\t%c\t%t"` (tab-separated name, severity, fixed version, CVEs, issue types). `%v` prints only when a released fix exists, which is exactly the fixable/unfixed split. If `--format` fails it parses the sentence output with a corrected regex. Output is trusted only when every line parses; otherwise GASP keeps the last good result and logs `packages: arch-audit failed, keeping previous findings: ...`. arch-audit now runs with its default database path (it only reads installed versions), which removes E. IgnorePkg updates are counted apart as `updates_ignored`: not pending and never flagged on their own, but one with a security fix is still flagged and listed with `ignored: true` (G).

Matches the code, per the checkupdates source: output `name old -> new`, exit 0 means updates, 2 means none, 1 means error; `-n/--nosync` exists; `CHECKUPDATES_DB` is honoured; color is off when stderr isn't a terminal.

## 1. Optional, before upgrading: snapshot of the year-old box

This is the one chance to see the overdue and stale rules fire for real. It needs a GASP binary built on another machine with Go 1.25.5 or newer, because installing anything on the old box first means a full upgrade.

On the build machine, from a checkout of main:

```
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o gasp ./cmd/gasp
```

Copy `gasp` to the mini PC as `~/gasp-test/gasp`. Don't run `pacman -Sy` on its own on the old box (partial upgrade).

```
mkdir -p ~/gasp-test/out
printf 'collection:\n  packages:\n    network_jitter: 0s\n' > ~/gasp-test/config.yaml
~/gasp-test/gasp --config ~/gasp-test/config.yaml --port 8080 > ~/gasp-test/out/gasp-pre.log 2>&1 &
sleep 15
curl -s localhost:8080/metrics > ~/gasp-test/out/metrics-pre.json
kill %1
```

Expected in `.packages` (checkupdates and arch-audit aren't installed yet):
- `manager: "pacman"`, `method: "pacman -Qu"`, `status: "ok"`
- `security_updates_pending: null`, interpretation mentions "install arch-audit to check"
- `metadata_age_hours` in the thousands, `days_since_upgrade` around 300+
- `needs_update: true`, reason `no upgrade in N days`, `state: "overdue"`
- `.summary.score` 5 lower than it would otherwise be, and the reason in `.summary.concerns`

## 2. Bring the box up to date and install the tools

```
sudo pacman -Sy archlinux-keyring && sudo pacman -Su
```

If key errors persist: `sudo pacman-key --init && sudo pacman-key --populate archlinux`, then retry. Merge any `.pacnew` files pacman reports.

Don't reboot yet if `linux` (or `linux-lts`) was upgraded: step 7 tests reboot detection first.

```
sudo pacman -S --needed pacman-contrib fakeroot arch-audit go git jq
```

## 3. Capture the real tool output (fixtures)

```
cd ~/gasp-test/out
pacman -Q pacman pacman-contrib fakeroot arch-audit > versions.txt
checkupdates --version >> versions.txt; arch-audit --version >> versions.txt
arch-audit --help > arch-audit-help.txt
checkupdates > checkupdates.txt; echo "exit $?" >> checkupdates.txt
arch-audit > arch-audit.txt; echo "exit $?" >> arch-audit.txt
arch-audit -c > arch-audit-cve.txt
arch-audit --json > arch-audit.json
pacman -Qu > pacman-qu.txt; echo "exit $?" >> pacman-qu.txt
uname -r > kernel.txt; ls /usr/lib/modules >> kernel.txt
```

Check by eye:
- [ ] `arch-audit --help` still lists `--dbpath`, `--format`, `--json`, `--source`. If a flag is gone or renamed, note it.
- [ ] Lines in `arch-audit.txt` start with the package name, not `Package ` (finding A), and fixes read `Update to at least` (finding B). If the box is fully patched the file may be empty; step 6 forces some output.
- [ ] `arch-audit --format "%n|%s|%v|%c|%t"` prints one line per package with those fields.
- [ ] `checkupdates.txt` is `name old -> new` lines with exit 0, or empty with exit 2.

## 4. Build GASP from the branch and run the live tests

```
cd ~/gasp-test && git clone -b fix/arch-audit-parser https://github.com/AcceleratedIndustries/gasp && cd gasp
go build -o ~/gasp-test/gasp ./cmd/gasp
go test -race ./...
make test-arch 2>&1 | tee ~/gasp-test/out/test-arch.txt
```

`make test-arch` runs `go test -tags archlive -v -count=1 -run Live ./internal/collectors/`. It runs the real tools and changes no packages; checkupdates syncs into a temp dir, and arch-audit downloads the security tracker.

- [ ] Build and `go test -race ./...` pass on Arch.
- [ ] `make test-arch` passes. What each test covers:
  - `TestLiveArchAuditVersion`: logs versions; fails if `--format` or `--source` is missing from `arch-audit --help`.
  - `TestLiveArchAuditFake`: real arch-audit against a fake tracker file (pacman with a released fix, bash with none, coreutils testing-only, one not installed). Both parsers must agree, including with `-c --show-testing`.
  - `TestLiveArchAuditReal`: the real tracker; every package arch-audit prints must be parsed by both parsers.
  - `TestLiveCheckupdates`: real network and `--nosync` checks; counts must match `checkupdates --nosync` and `pacman -Qu` (minus ignored), and GASP's ignored list must match pacman's `[ignored]` lines. If anything is pending, it also checks that a pending package with a released fix is marked as a security update. It skips that part when nothing is pending (see the nano downgrade in step 6).
  - `TestLiveReboot`, `TestLiveLogAndMetadata`, `TestLiveCollector`: reboot detection, pacman.log and sync DB times, and one full collector run (logs the whole packages block).
- [ ] The raw output in `test-arch.txt` replaces the hand-written fixtures in `internal/collectors/testdata/packages/` (`arch-audit.txt`, `arch-audit-format.txt`).

## 5. Run GASP and force the daily network check

GASP needs a config file, even a minimal one (step 1's `~/gasp-test/config.yaml` works). The daily check (checkupdates, then arch-audit) runs at startup when `packages-state.json` has no `last_network_check` or it's over 24 hours old. Otherwise it waits for 03:30 plus jitter.

To force it at any time:

```
kill %1 2>/dev/null
jq 'del(.last_network_check)' ~/.local/state/gasp/packages-state.json > /tmp/ps.json && mv /tmp/ps.json ~/.local/state/gasp/packages-state.json
~/gasp-test/gasp --config ~/gasp-test/config.yaml --port 8080 > ~/gasp-test/out/gasp.log 2>&1 &
sleep 30
curl -s localhost:8080/metrics | jq .packages > ~/gasp-test/out/metrics-1.json
```

(First run: there's no state file yet, so just start GASP.) Deleting the whole state file also forces it, but it drops first-seen times and the cached arch-audit result. Another way: set `network_check_at` a few minutes ahead with `network_jitter: 0s`; the scheduler ticks every 5 minutes, so it fires within 5 minutes of that time.

- [ ] `last_network_check` is set and `method` is `checkupdates + arch-audit`.
- [ ] `gasp.log` has no `packages:` error lines (a failed network check logs `packages: network check failed: ...`).
- [ ] `check_duration_ms` is reasonable (seconds, not near the 60 s timeout).

## 6. Check the parsers against real output

Pending counts:

```
ls -l ~/.local/state/gasp/checkup-db/ ~/.local/state/gasp/checkup-db/sync/
CHECKUPDATES_DB=~/.local/state/gasp/checkup-db checkupdates --nosync; echo "exit $?"
```

- [ ] `sync/` holds `core.db` and `extra.db` (the `local` symlink no longer matters on the branch).
- [ ] `updates_pending` equals the number of lines from `checkupdates --nosync`.
- [ ] After an hour, or a pacman change, the local check reruns with `method: "checkupdates --nosync + arch-audit"`.

A fully upgraded box has nothing pending. To make one pending update, downgrade a harmless leaf package from the cache (undo later with `sudo pacman -Syu`):

```
ls /var/cache/pacman/pkg/nano-*
sudo pacman -U /var/cache/pacman/pkg/nano-<older version>.pkg.tar.zst
```

Within 5 minutes /metrics should show `updates_pending: 1`, `state: "updates_pending"`, `needs_update: false`.

Security parsing with real arch-audit output: point arch-audit at a fake tracker file so it reports the downgraded package, using a wrapper GASP finds first on PATH.

```
mkdir -p ~/gasp-test/bin
NANO_NEW=$(CHECKUPDATES_DB=~/.local/state/gasp/checkup-db checkupdates --nosync | awk '$1=="nano"{print $4}')
cat > ~/gasp-test/fake-avgs.json <<EOF
[
 {"name":"AVG-9001","packages":["nano"],"status":"Fixed","type":"arbitrary code execution","severity":"High","fixed":"$NANO_NEW","issues":["CVE-2099-0001"]},
 {"name":"AVG-9002","packages":["less"],"status":"Vulnerable","type":"denial of service","severity":"Medium","fixed":null,"issues":["CVE-2099-0002"]}
]
EOF
printf '#!/bin/sh\nexec /usr/bin/arch-audit --source "$HOME/gasp-test/fake-avgs.json" "$@"\n' > ~/gasp-test/bin/arch-audit
chmod +x ~/gasp-test/bin/arch-audit
PATH=~/gasp-test/bin:$PATH arch-audit | tee ~/gasp-test/out/arch-audit-fake.txt
```

Then restart GASP with that PATH and force the network check (step 5's jq line):

```
kill %1; PATH=~/gasp-test/bin:$PATH ~/gasp-test/gasp --config ~/gasp-test/config.yaml --port 8080 > ~/gasp-test/out/gasp.log 2>&1 &
```

- [ ] On main (unfixed) this shows the bug: `security_updates_pending: 0`, `vulnerable_unfixed: 0`, "none of them security".
- [ ] On the branch it should show: `security_updates_pending: 1`, `security_max_severity: "high"`, `security_updates[0].name: "nano"`, `vulnerable_unfixed: 1`, `state: "security_updates_pending"`, a "1 security update pending (max severity: high)" reason, and the summary score 10 lower.
- [ ] Only `nano` is named in /metrics; `less` appears only as a count.

Remove `~/gasp-test/bin` from PATH when done.

### IgnorePkg (commit 8801075)

With nano still downgraded and the fake-tracker wrapper still on PATH:

```
sudo sed -i 's/^#\?IgnorePkg *=.*/IgnorePkg = nano/' /etc/pacman.conf
grep '^IgnorePkg' /etc/pacman.conf
```

Restart GASP so it re-runs the network check, then within 5 minutes:

- [ ] `updates_pending: 0` and `updates_ignored: 1`.
- [ ] `security_updates_pending: 1`, `security_updates[0]` is nano with `ignored: true`, `needs_update: true`.
- [ ] The reason reads "1 security update pending (max severity: high, 1 held back by IgnorePkg)".
- [ ] `interpretation` says "nothing pending outside IgnorePkg" and "1 security update held back by IgnorePkg (nano)".
- [ ] Without the wrapper on PATH: `updates_ignored: 1`, nothing flagged, `needs_update: false`.

Put pacman.conf back afterwards (`sudo sed -i 's/^IgnorePkg = nano$/#IgnorePkg   =/' /etc/pacman.conf`).

## 7. Reboot detection

Right after an upgrade that replaced the kernel, before rebooting:

```
uname -r; ls /usr/lib/modules
```

- [ ] The running kernel's directory is gone, and /metrics shows `reboot_required: true` with `running kernel <x> is no longer installed`, `state: "reboot_required"` (unless security outranks it), score 5 lower.
- [ ] If the old directory is still there (leftover DKMS or out-of-tree module files), detection misses it. Note what's inside it.
- [ ] After rebooting and restarting GASP: `reboot_required: false`, "no reboot needed".

Also: start `sudo pacman -Syu` and leave it at the confirm prompt. Within 5 minutes `update_in_progress` should be `true`. Answer no afterwards.

## 8. The 7-day rule

Quick version with tiny thresholds, in `~/gasp-test/config.yaml`:

```
collection:
  packages:
    network_jitter: 0s
    stale_after: 1m
    overdue_after:
      pacman: 2m
```

Restart GASP more than 2 minutes after the last upgrade.

- [ ] Interpretation says the package lists are old ("so counts may be out of date").
- [ ] `needs_update: true`, reason `no upgrade in 0 days` (the 0 is expected with minute thresholds), `state: "overdue"`, score 5 lower.

The "waiting" path, with defaults restored and the nano downgrade still pending: stop GASP, set nano's first-seen time back 8 days, restart.

```
kill %1
jq --arg t "$(date -u -d '8 days ago' +%Y-%m-%dT%H:%M:%SZ)" '.first_seen |= with_entries(if (.key|startswith("nano@")) then .value=$t else . end)' ~/.local/state/gasp/packages-state.json > /tmp/ps.json && mv /tmp/ps.json ~/.local/state/gasp/packages-state.json
```

- [ ] `oldest_pending_days: 8`, reason `an update has been waiting 8 days`, `state: "overdue"`.

(A `pacman -U` downgrade logs `downgraded`, not `upgraded`, so it doesn't reset `last_upgrade`.)

## 9. /metrics fields to look at

`jq .packages` and `jq .summary` on `curl -s localhost:8080/metrics`:

- `manager` pacman; `method` one of `checkupdates`, `checkupdates --nosync`, `pacman -Qu`, plus ` + arch-audit` once arch-audit has run
- `status` ok (stale means a check failed after an earlier success; read `error`)
- `state`, `needs_update`, `needs_update_reasons`
- `updates_pending`, `updates_ignored` (IgnorePkg/IgnoreGroup, not part of pending; omitted when unknown), `security_updates_pending` (null means unknown), `vulnerable_unfixed`, `security_max_severity`, `security_updates` (names security packages only; `ignored: true` on one held back by IgnorePkg)
- `reboot_required`, `reboot_reasons`, `running_kernel`
- `metadata_age_hours`: age of `/var/lib/pacman/sync/*.db`. pacman sets their mtime to the mirror's time, so right after `pacman -Sy` this is the mirror's age, not zero.
- `last_upgrade`, `days_since_upgrade`, `oldest_pending_days`
- `last_checked`, `last_network_check`, `check_duration_ms`, `update_in_progress`, `interpretation`
- `.summary.concerns` holds one line per reason; `.summary.score` drops by 10 for security, 5 for reboot, 5 for overdue

## 10. What to send back

The whole `~/gasp-test/out/` folder (including `test-arch.txt`), plus a note on any box above that didn't match. The real `arch-audit.txt`, `arch-audit-fake.txt`, `checkupdates.txt` and the arch-audit lines in `test-arch.txt` become the new test fixtures. Don't commit the folder to the repo (it's public and the folder lists the machine's packages and vulnerabilities); pack it with `tar czf ~/gasp-test/arch-results.tar.gz -C ~/gasp-test out` and send the file over.

Clean up: `sudo pacman -Syu` (undoes the nano downgrade), remove `~/gasp-test/bin`.
