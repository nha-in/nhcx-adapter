package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// DefaultRepo is the GitHub repository whose releases are consulted. The
// build can override it with -X nhcx-gateway/internal/update.DefaultRepo=…
// and the operator with NHCX_GATEWAY_UPDATE_REPO.
var DefaultRepo = "nha-in/nhcx-adapter"

// Name is the binary's base name inside the release archives.
const Name = "nhcx-gateway"

// Release is one GitHub release: a tag with its downloadable archives.
type Release struct {
	Tag        string    `json:"tag_name"`
	Name       string    `json:"name"`
	Notes      string    `json:"body"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
	Published  time.Time `json:"published_at"`
	URL        string    `json:"html_url"`
	Assets     []Asset   `json:"assets"`

	Version Version `json:"-"` // parsed Tag; zero when the tag is not a version
}

// Asset is one file attached to a release.
type Asset struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	APIURL      string `json:"url"`                  // needs Accept: application/octet-stream (private repos)
	DownloadURL string `json:"browser_download_url"` // public repos
}

// Client talks to the GitHub REST API for one repository.
type Client struct {
	Repo    string       // "owner/name"
	Token   string       // optional; raises the rate limit and unlocks private repos
	APIBase string       // defaults to https://api.github.com
	HTTP    *http.Client // defaults to a 30 s client
}

// NewClient builds a client for repo (DefaultRepo when empty), taking the
// repository from NHCX_GATEWAY_UPDATE_REPO, the token from
// NHCX_GATEWAY_GITHUB_TOKEN or GITHUB_TOKEN, and the API base from
// NHCX_GATEWAY_GITHUB_API (GitHub Enterprise) when set.
func NewClient(repo string) *Client {
	if env := os.Getenv("NHCX_GATEWAY_UPDATE_REPO"); env != "" {
		repo = env
	}
	if repo == "" {
		repo = DefaultRepo
	}
	token := os.Getenv("NHCX_GATEWAY_GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	return &Client{Repo: repo, Token: token, APIBase: os.Getenv("NHCX_GATEWAY_GITHUB_API")}
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) apiBase() string {
	if c.APIBase != "" {
		return strings.TrimRight(c.APIBase, "/")
	}
	return "https://api.github.com"
}

func (c *Client) newRequest(ctx context.Context, url, accept string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", Name+"-updater")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	return req, nil
}

// Releases lists every published release, newest version first. Drafts and
// tags that are not versions are skipped; pre-releases are included and
// flagged.
func (c *Client) Releases(ctx context.Context) ([]Release, error) {
	var all []Release
	for page := 1; page <= 10; page++ {
		req, err := c.newRequest(ctx, fmt.Sprintf("%s/repos/%s/releases?per_page=100&page=%d", c.apiBase(), c.Repo, page), "application/vnd.github+json")
		if err != nil {
			return nil, err
		}
		resp, err := c.http().Do(req)
		if err != nil {
			return nil, fmt.Errorf("github: %w", err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("github: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, apiError(c.Repo, resp, body)
		}
		var page []Release
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("github: unexpected response: %w", err)
		}
		all = append(all, page...)
		if len(page) < 100 {
			break
		}
	}
	out := all[:0]
	for _, r := range all {
		if r.Draft {
			continue
		}
		v, ok := Parse(r.Tag)
		if !ok {
			continue
		}
		r.Version = v
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return Compare(out[i].Version, out[j].Version) > 0 })
	return out, nil
}

// apiError turns a non-200 answer into something an operator can act on.
func apiError(repo string, resp *http.Response, body []byte) error {
	var msg struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &msg)
	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("github: repository %s not found (private? set GITHUB_TOKEN; wrong repo? set NHCX_GATEWAY_UPDATE_REPO)", repo)
	case http.StatusUnauthorized:
		return fmt.Errorf("github: token rejected: %s", msg.Message)
	case http.StatusForbidden, http.StatusTooManyRequests:
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return errors.New("github: API rate limit reached — set GITHUB_TOKEN or try later")
		}
		return fmt.Errorf("github: forbidden: %s", msg.Message)
	}
	return fmt.Errorf("github: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(msg.Message))
}

// Latest is the newest release, ignoring pre-releases unless pre is set.
func Latest(releases []Release, pre bool) *Release {
	for i := range releases {
		if pre || !releases[i].Prerelease && releases[i].Version.Pre == "" {
			return &releases[i]
		}
	}
	return nil
}

// Find returns the release whose tag is tag (with or without the leading v).
func Find(releases []Release, tag string) *Release {
	want, ok := Parse(tag)
	if !ok {
		return nil
	}
	for i := range releases {
		if Compare(releases[i].Version, want) == 0 && releases[i].Version.Pre == want.Pre {
			return &releases[i]
		}
	}
	return nil
}

// ArchiveName is the archive scripts/build.sh produces for one platform.
func ArchiveName(tag, goos, goarch string) string {
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("%s_%s_%s_%s%s", Name, tag, goos, goarch, ext)
}

// AssetFor picks the archive for a platform, or nil when the release has
// none for it.
func (r *Release) AssetFor(goos, goarch string) *Asset {
	want := ArchiveName(r.Tag, goos, goarch)
	for i := range r.Assets {
		if r.Assets[i].Name == want {
			return &r.Assets[i]
		}
	}
	return nil
}

// Checksums is the SHA256SUMS asset, or nil.
func (r *Release) Checksums() *Asset {
	for i := range r.Assets {
		if r.Assets[i].Name == "SHA256SUMS" {
			return &r.Assets[i]
		}
	}
	return nil
}

// Check summarises how the installed version relates to the releases.
type Check struct {
	Current   Version  // zero when the running build has no parseable version
	Known     bool     // Current parsed
	Latest    *Release // newest stable release, if any
	Available bool     // Latest is newer than Current
}

// Compare works out whether a newer stable release exists than current.
func CompareCurrent(current string, releases []Release) Check {
	var ch Check
	ch.Current, ch.Known = Parse(current)
	ch.Latest = Latest(releases, false)
	if ch.Latest != nil && ch.Known {
		ch.Available = Compare(ch.Latest.Version, ch.Current) > 0
	}
	return ch
}
