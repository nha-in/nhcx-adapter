package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Version
		ok   bool
	}{
		{"v1.2.3", Version{Major: 1, Minor: 2, Patch: 3}, true},
		{"1.2.3", Version{Major: 1, Minor: 2, Patch: 3}, true},
		{"v1.2", Version{Major: 1, Minor: 2}, true},
		{"v1.2.3-rc1", Version{Major: 1, Minor: 2, Patch: 3, Pre: "rc1"}, true},
		{"v1.2.3-4-gabcdef1", Version{Major: 1, Minor: 2, Patch: 3, Ahead: 4}, true},
		{"v1.2.3-4-gabcdef1-dirty", Version{Major: 1, Minor: 2, Patch: 3, Ahead: 4, Dirty: true}, true},
		{"v1.2.3-dirty", Version{Major: 1, Minor: 2, Patch: 3, Dirty: true}, true},
		{"v1.2.3-rc1-2-g1234567", Version{Major: 1, Minor: 2, Patch: 3, Pre: "rc1", Ahead: 2}, true},
		{"dev", Version{}, false},
		{"unknown", Version{}, false},
		{"", Version{}, false},
		{"abcdef1", Version{}, false},
	}
	for _, c := range cases {
		got, ok := Parse(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("Parse(%q) = %+v, %v; want %+v, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestCompare(t *testing.T) {
	order := []string{"v0.9.0", "v1.0.0-rc1", "v1.0.0-rc2", "v1.0.0", "v1.0.0-3-gabc123", "v1.0.1", "v1.1.0", "v2.0.0"}
	for i := range order {
		for j := range order {
			a, _ := Parse(order[i])
			b, _ := Parse(order[j])
			want := sign(i - j)
			if got := Compare(a, b); got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", order[i], order[j], got, want)
			}
		}
	}
}

func TestVerifySum(t *testing.T) {
	data := []byte("hello")
	sum := sha256.Sum256(data)
	sums := []byte(fmt.Sprintf("%s  other.tar.gz\n%s  nhcx-adapter_v1.0.0_linux_amd64.tar.gz\n", strings.Repeat("0", 64), hex.EncodeToString(sum[:])))
	if err := VerifySum(sums, "nhcx-adapter_v1.0.0_linux_amd64.tar.gz", data); err != nil {
		t.Fatal(err)
	}
	if err := VerifySum(sums, "nhcx-adapter_v1.0.0_linux_amd64.tar.gz", []byte("tampered")); err == nil {
		t.Fatal("tampered data passed")
	}
	if err := VerifySum(sums, "missing.zip", data); err == nil {
		t.Fatal("missing entry passed")
	}
}

func tarGz(t *testing.T, dir, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		body []byte
	}{{dir + "/README.md", []byte("readme")}, {dir + "/" + name, content}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(f.body)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func zipArchive(t *testing.T, dir, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create(dir + "/README.md")
	w.Write([]byte("readme"))
	w, _ = zw.Create(dir + "/" + name)
	w.Write(content)
	zw.Close()
	return buf.Bytes()
}

func TestExtract(t *testing.T) {
	bin := []byte("#!/bin/sh\necho binary\n")
	got, err := Extract("nhcx-adapter_v1.0.0_linux_amd64.tar.gz", tarGz(t, "nhcx-adapter_v1.0.0_linux_amd64", "nhcx-adapter", bin))
	if err != nil || !bytes.Equal(got, bin) {
		t.Fatalf("tar: %v %q", err, got)
	}
	got, err = Extract("nhcx-adapter_v1.0.0_windows_amd64.zip", zipArchive(t, "nhcx-adapter_v1.0.0_windows_amd64", "nhcx-adapter.exe", bin))
	if err != nil || !bytes.Equal(got, bin) {
		t.Fatalf("zip: %v %q", err, got)
	}
	if _, err := Extract("x.tar.gz", tarGz(t, "d", "something-else", bin)); err == nil {
		t.Fatal("archive without the binary accepted")
	}
}

func TestInstall(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "nhcx-adapter")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Install(exe, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "new" {
		t.Fatalf("binary = %q", got)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(exe)
		if st.Mode().Perm()&0o111 == 0 {
			t.Fatal("not executable")
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".new-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

// fakeGitHub serves a releases list and its assets the way api.github.com
// and objects.githubusercontent.com do.
func fakeGitHub(t *testing.T, releases []Release, files map[string][]byte) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/repos/o/r/releases"):
			if r.Header.Get("Authorization") != "" && r.Header.Get("Authorization") != "Bearer secret" {
				w.WriteHeader(401)
				return
			}
			var out []Release
			for _, rel := range releases {
				for i := range rel.Assets {
					rel.Assets[i].DownloadURL = srv.URL + "/download/" + rel.Assets[i].Name
					rel.Assets[i].APIURL = srv.URL + "/api-asset/" + rel.Assets[i].Name
				}
				out = append(out, rel)
			}
			json.NewEncoder(w).Encode(out)
		case strings.HasPrefix(r.URL.Path, "/download/"):
			name := strings.TrimPrefix(r.URL.Path, "/download/")
			if b, ok := files[name]; ok {
				w.Write(b)
				return
			}
			w.WriteHeader(404)
		case strings.HasPrefix(r.URL.Path, "/api-asset/"):
			if r.Header.Get("Accept") != "application/octet-stream" || r.Header.Get("Authorization") != "Bearer secret" {
				w.WriteHeader(403)
				return
			}
			name := strings.TrimPrefix(r.URL.Path, "/api-asset/")
			w.Write(files[name])
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEndToEnd(t *testing.T) {
	goos, goarch := runtime.GOOS, runtime.GOARCH
	binName := Name
	if goos == "windows" {
		binName += ".exe"
	}
	newBin := []byte("new binary v1.1.0")
	oldBin := []byte("old binary v1.0.0")
	files := map[string][]byte{}
	var sums strings.Builder
	for tag, bin := range map[string][]byte{"v1.1.0": newBin, "v1.0.0": oldBin} {
		name := ArchiveName(tag, goos, goarch)
		dir := strings.TrimSuffix(strings.TrimSuffix(name, ".tar.gz"), ".zip")
		if goos == "windows" {
			files[name] = zipArchive(t, dir, binName, bin)
		} else {
			files[name] = tarGz(t, dir, binName, bin)
		}
		sum := sha256.Sum256(files[name])
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	files["SHA256SUMS"] = []byte(sums.String())
	assets := func(tag string) []Asset {
		return []Asset{{Name: ArchiveName(tag, goos, goarch)}, {Name: "SHA256SUMS"}, {Name: ArchiveName(tag, "plan9", "mips")}}
	}
	releases := []Release{
		{Tag: "v1.0.0", Assets: assets("v1.0.0")},
		{Tag: "v2.0.0-rc1", Prerelease: true, Assets: assets("v2.0.0-rc1")},
		{Tag: "v1.1.0", Assets: assets("v1.1.0")},
		{Tag: "not-a-version"},
		{Tag: "v9.9.9", Draft: true},
	}
	srv := fakeGitHub(t, releases, files)

	for _, token := range []string{"", "secret"} {
		c := &Client{Repo: "o/r", APIBase: srv.URL, Token: token}
		rels, err := c.Releases(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var tags []string
		for _, r := range rels {
			tags = append(tags, r.Tag)
		}
		if got := strings.Join(tags, " "); got != "v2.0.0-rc1 v1.1.0 v1.0.0" {
			t.Fatalf("releases = %s", got)
		}
		ch := CompareCurrent("v1.0.0", rels)
		if !ch.Available || ch.Latest.Tag != "v1.1.0" {
			t.Fatalf("check = %+v", ch)
		}
		if ch := CompareCurrent("v1.1.0", rels); ch.Available {
			t.Fatalf("v1.1.0 should be current: %+v", ch)
		}
		if ch := CompareCurrent("dev", rels); ch.Known || ch.Available {
			t.Fatalf("dev build: %+v", ch)
		}
		if Find(rels, "1.0.0") == nil || Find(rels, "v3.0.0") != nil {
			t.Fatal("Find")
		}

		rel := Find(rels, "v1.1.0")
		a := rel.AssetFor(goos, goarch)
		if a == nil {
			t.Fatal("no asset for this platform")
		}
		var calls int
		archive, err := c.Download(context.Background(), rel, a, func(done, total int64) { calls++ })
		if err != nil {
			t.Fatal(err)
		}
		if calls == 0 {
			t.Fatal("no progress reported")
		}
		bin, err := Extract(a.Name, archive)
		if err != nil {
			t.Fatal(err)
		}
		exe := filepath.Join(t.TempDir(), binName)
		os.WriteFile(exe, oldBin, 0o755)
		if err := Install(exe, bin); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(exe); !bytes.Equal(got, newBin) {
			t.Fatalf("installed %q", got)
		}
	}

	// A corrupted archive must be refused by the checksum.
	files[ArchiveName("v1.0.0", goos, goarch)] = append(files[ArchiveName("v1.0.0", goos, goarch)], 0)
	c := &Client{Repo: "o/r", APIBase: srv.URL}
	rels, _ := c.Releases(context.Background())
	rel := Find(rels, "v1.0.0")
	if _, err := c.Download(context.Background(), rel, rel.AssetFor(goos, goarch), nil); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("corrupted download accepted: %v", err)
	}

	// Errors are explained.
	c = &Client{Repo: "o/missing", APIBase: srv.URL}
	if _, err := c.Releases(context.Background()); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("404: %v", err)
	}
}
