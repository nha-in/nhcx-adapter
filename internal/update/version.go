// Package update checks GitHub releases for other versions of this binary
// and swaps the running executable for one of them — newer or older. The
// release layout is the one scripts/build.sh and the CI workflow produce:
// one archive per platform named nhcx-adapter_<tag>_<os>_<arch>.tar.gz
// (.zip on Windows) plus a SHA256SUMS file.
package update

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Version is a parsed release tag such as v1.2.3 or v1.2.3-rc1, or a
// git-describe build such as v1.2.3-4-gabcdef-dirty.
type Version struct {
	Major, Minor, Patch int
	Pre                 string // semver pre-release ("rc1"), empty for a release
	Ahead               int    // commits after the tag, for git-describe builds
	Dirty               bool
}

// describeSuffix matches what git describe appends after the tag:
// -<commits>-g<sha>[-dirty].
var describeSuffix = regexp.MustCompile(`-(\d+)-g[0-9a-f]+(-dirty)?$`)

// Parse reads a version string. It returns false for anything that does not
// start with a dotted number ("dev", "unknown", "").
func Parse(s string) (Version, bool) {
	var v Version
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return v, false
	}
	if strings.HasSuffix(s, "-dirty") && !describeSuffix.MatchString(s) {
		v.Dirty = true
		s = strings.TrimSuffix(s, "-dirty")
	}
	if m := describeSuffix.FindStringSubmatch(s); m != nil {
		v.Ahead, _ = strconv.Atoi(m[1])
		v.Dirty = v.Dirty || m[2] != ""
		s = s[:len(s)-len(m[0])]
	}
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		if s[i] == '-' {
			v.Pre = s[i+1:]
		}
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return Version{}, false
	}
	nums := [3]int{}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return Version{}, false
		}
		nums[i] = n
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	return v, true
}

// String renders the version back as a tag-style string.
func (v Version) String() string {
	s := fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	if v.Ahead > 0 {
		s += fmt.Sprintf("+%d", v.Ahead)
	}
	if v.Dirty {
		s += "-dirty"
	}
	return s
}

// Compare orders two versions: -1 if v is older than o, 0 if equal, 1 if
// newer. A pre-release sorts before its release; a git-describe build
// sorts after the tag it describes.
func Compare(v, o Version) int {
	for _, d := range []int{v.Major - o.Major, v.Minor - o.Minor, v.Patch - o.Patch} {
		if d != 0 {
			return sign(d)
		}
	}
	switch {
	case v.Pre == "" && o.Pre != "":
		return 1
	case v.Pre != "" && o.Pre == "":
		return -1
	case v.Pre != o.Pre:
		return comparePre(v.Pre, o.Pre)
	}
	return sign(v.Ahead - o.Ahead)
}

// comparePre orders pre-release identifiers the semver way: dot-separated
// fields, numeric fields compared as numbers and before alphanumerics.
func comparePre(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				return sign(an - bn)
			}
		case aerr == nil:
			return -1
		case berr == nil:
			return 1
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}
	return sign(len(as) - len(bs))
}

func sign(d int) int {
	switch {
	case d < 0:
		return -1
	case d > 0:
		return 1
	}
	return 0
}
