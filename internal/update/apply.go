package update

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Progress receives download progress: bytes so far and the total (-1 when
// unknown). It may be nil.
type Progress func(done, total int64)

// Executable is the path of the running binary, symlinks resolved.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return exe, nil
}

// Download fetches an asset and returns its bytes, verifying the SHA-256
// against the release's SHA256SUMS when it has one.
func (c *Client) Download(ctx context.Context, rel *Release, a *Asset, progress Progress) ([]byte, error) {
	data, err := c.fetchAsset(ctx, a, progress)
	if err != nil {
		return nil, err
	}
	sums := rel.Checksums()
	if sums == nil {
		return data, nil
	}
	sumData, err := c.fetchAsset(ctx, sums, nil)
	if err != nil {
		return nil, fmt.Errorf("SHA256SUMS: %w", err)
	}
	if err := VerifySum(sumData, a.Name, data); err != nil {
		return nil, err
	}
	return data, nil
}

// fetchAsset streams one asset. With a token the API URL is used (the only
// route that works for private repositories); otherwise the public
// download URL.
func (c *Client) fetchAsset(ctx context.Context, a *Asset, progress Progress) ([]byte, error) {
	url := a.DownloadURL
	if c.Token != "" && a.APIURL != "" {
		url = a.APIURL
	}
	if url == "" {
		return nil, fmt.Errorf("asset %s has no download URL", a.Name)
	}
	req, err := c.newRequest(ctx, url, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	client := c.http()
	// Archives can be large and links slow; the API timeout is for headers.
	dl := *client
	dl.Timeout = 0
	resp, err := dl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", a.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("download %s: %w", a.Name, apiError(c.Repo, resp, body))
	}
	total := resp.ContentLength
	if total <= 0 && a.Size > 0 {
		total = a.Size
	}
	var buf bytes.Buffer
	if total > 0 {
		buf.Grow(int(total))
	}
	chunk := make([]byte, 256<<10)
	var done int64
	last := time.Time{}
	for {
		n, err := resp.Body.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			done += int64(n)
			if progress != nil && (time.Since(last) > 100*time.Millisecond || err == io.EOF) {
				progress(done, total)
				last = time.Now()
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", a.Name, err)
		}
	}
	if progress != nil {
		progress(done, total)
	}
	return buf.Bytes(), nil
}

// VerifySum checks data against the "<hex>  <name>" lines of a SHA256SUMS
// file. A missing entry is an error: a release that ships checksums must
// cover every archive.
func VerifySum(sums []byte, name string, data []byte) error {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		file := strings.TrimPrefix(fields[len(fields)-1], "*")
		if path.Base(file) != name {
			continue
		}
		sum := sha256.Sum256(data)
		if !strings.EqualFold(fields[0], hex.EncodeToString(sum[:])) {
			return fmt.Errorf("%s: checksum mismatch (download corrupted or tampered with)", name)
		}
		return nil
	}
	return fmt.Errorf("%s: not listed in SHA256SUMS", name)
}

// Extract pulls the nhcx-gateway binary out of a release archive (.tar.gz
// or .zip, decided by name).
func Extract(name string, archive []byte) ([]byte, error) {
	want := Name
	if strings.HasSuffix(name, ".zip") {
		want += ".exe"
		zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		for _, f := range zr.File {
			if path.Base(f.Name) != want || f.FileInfo().IsDir() {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
		return nil, fmt.Errorf("%s: no %s inside", name, want)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%s: no %s inside", name, want)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if h.Typeflag == tar.TypeReg && path.Base(h.Name) == want {
			return io.ReadAll(tr)
		}
	}
}

// Install writes binary over the executable at exe. The new file is
// written beside it and renamed into place, so a failure never leaves a
// half-written binary. On Windows the running image cannot be overwritten
// but can be renamed, so the old one is parked as <exe>.old and removed
// by CleanupOld on the next start.
func Install(exe string, binary []byte) error {
	info, err := os.Stat(exe)
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(exe)+".new-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s: %w (run as a user who owns the binary, or with sudo)", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { os.Remove(tmpName) }
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpName, info.Mode().Perm()|0o111); err != nil {
		cleanup()
		return err
	}
	if runtime.GOOS == "windows" {
		old := exe + ".old"
		if os.Remove(old); fileExists(old) {
			// Still running from an earlier update; park this one elsewhere.
			old = fmt.Sprintf("%s.old-%d", exe, time.Now().Unix())
		}
		if err := os.Rename(exe, old); err != nil {
			cleanup()
			return fmt.Errorf("cannot move the current binary aside: %w", err)
		}
		if err := os.Rename(tmpName, exe); err != nil {
			os.Rename(old, exe) // put it back
			cleanup()
			return err
		}
		os.Remove(old) // fails while it is running; CleanupOld gets it later
		return nil
	}
	if err := os.Rename(tmpName, exe); err != nil {
		cleanup()
		return err
	}
	return nil
}

// CleanupOld removes the <exe>.old* files left by Windows updates, once
// nothing runs them any more. Safe to call at every start.
func CleanupOld() {
	exe, err := Executable()
	if err != nil {
		return
	}
	matches, _ := filepath.Glob(exe + ".old*")
	for _, m := range matches {
		os.Remove(m)
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// InstalledVersion runs `exe version` and returns its first line, to
// confirm what was just installed actually starts.
func InstalledVersion(ctx context.Context, exe string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "version")
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return line, nil
}
