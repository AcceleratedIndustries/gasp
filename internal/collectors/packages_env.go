package collectors

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// cmdResult is the outcome of running one external command.
type cmdResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// cmdRunner runs package manager commands. Tests replace it with a fake.
type cmdRunner interface {
	// Run executes name with args and extra environment entries. A non-zero
	// exit status is reported in ExitCode, not as an error; err is set only
	// when the command could not be run or was killed (for example by the
	// context timeout).
	Run(ctx context.Context, env []string, name string, args ...string) (cmdResult, error)
	// LookPath reports whether a command is installed.
	LookPath(name string) (string, error)
}

// maxCommandOutput caps how much output is kept from one command.
const maxCommandOutput = 8 << 20

// cappedBuffer keeps at most limit bytes and silently drops the rest.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

// execRunner runs real commands: no shell, C locale, low CPU priority.
type execRunner struct{}

func (execRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (execRunner) Run(ctx context.Context, env []string, name string, args ...string) (cmdResult, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "NO_COLOR=1")
	cmd.Env = append(cmd.Env, env...)
	stdout := &cappedBuffer{limit: maxCommandOutput}
	stderr := &cappedBuffer{limit: maxCommandOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	if err := cmd.Start(); err != nil {
		return cmdResult{}, err
	}
	// Best effort: a package check should never compete with real work.
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, cmd.Process.Pid, 10)

	err := cmd.Wait()
	res := cmdResult{Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes()}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	return res, err
}

// pkgFS reads system files under a root directory, so tests can point it at
// a temporary tree.
type pkgFS struct {
	root string
}

func (f pkgFS) path(p string) string { return filepath.Join(f.root, p) }

func (f pkgFS) stat(p string) (os.FileInfo, error) { return os.Stat(f.path(p)) }

func (f pkgFS) exists(p string) bool {
	_, err := os.Stat(f.path(p))
	return err == nil
}

func (f pkgFS) readFile(p string) ([]byte, error) { return os.ReadFile(f.path(p)) }

func (f pkgFS) readDir(p string) ([]os.DirEntry, error) { return os.ReadDir(f.path(p)) }

// readTail returns at most the last n bytes of a file.
func (f pkgFS) readTail(p string, n int64) ([]byte, error) {
	file, err := os.Open(f.path(p))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	start := int64(0)
	if info.Size() > n {
		start = info.Size() - n
	}
	buf := make([]byte, info.Size()-start)
	_, err = file.ReadAt(buf, start)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf, nil
}

// readGzip returns the decompressed contents of a gzip file, at most n bytes.
func (f pkgFS) readGzip(p string, n int64) ([]byte, error) {
	file, err := os.Open(f.path(p))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	zr, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, n))
}

// osRelease returns ID and ID_LIKE from /etc/os-release (or
// /usr/lib/os-release), lower-cased.
func (f pkgFS) osRelease() (id string, idLike []string) {
	data, err := f.readFile("/etc/os-release")
	if err != nil {
		data, err = f.readFile("/usr/lib/os-release")
		if err != nil {
			return "", nil
		}
	}
	return parseOSRelease(data)
}

func parseOSRelease(data []byte) (id string, idLike []string) {
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		value = strings.ToLower(strings.Trim(value, `"'`))
		switch key {
		case "ID":
			id = value
		case "ID_LIKE":
			idLike = strings.Fields(value)
		}
	}
	return id, idLike
}

// runningCommands reports which of the given process names are running,
// by reading /proc/*/comm.
func (f pkgFS) runningCommands(names map[string]bool) []string {
	entries, err := f.readDir("/proc")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var found []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "" || e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		data, err := f.readFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(data))
		if names[comm] && !seen[comm] {
			seen[comm] = true
			found = append(found, comm)
		}
	}
	return found
}
