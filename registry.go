package pkgguard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// PackageInfo is what the registry says about one package version.
type PackageInfo struct {
	Exists           bool
	Version          string // the version this command would install (best effort for ranges)
	VersionMissing   bool   // an exact version was requested but the registry has no such version
	VersionPublished time.Time
	Created          time.Time
	Versions         map[string]time.Time // every version and its publish time
	Scripts          map[string]string    // install-time scripts of Version (npm: preinstall/install/postinstall/prepare)
	GypFile          bool                 // npm: binding.gyp present, so node-gyp runs at install
	Dependencies     []string             // direct runtime dependency names (npm)
	TarballURL       string
}

// OlderThan returns the newest version published at least minAge ago.
func (p *PackageInfo) OlderThan(minAge time.Duration, now time.Time) string {
	type vt struct {
		v string
		t time.Time
	}
	var all []vt
	for v, t := range p.Versions {
		if !t.IsZero() && now.Sub(t) >= minAge && !strings.ContainsAny(v, "-+") {
			all = append(all, vt{v, t})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.After(all[j].t) })
	if len(all) == 0 {
		return ""
	}
	return all[0].v
}

// EvidenceFile is a file read from a package archive (never executed).
type EvidenceFile struct {
	Path    string
	Content string
}

// Registry looks packages up. The default implementation talks to the public
// npm and PyPI registries; tests supply a fake.
type Registry interface {
	Lookup(ctx context.Context, eco, name, spec string) (*PackageInfo, error)
	// WeeklyDownloads returns last week's download count (npm: api.npmjs.org, PyPI: pypistats.org).
	WeeklyDownloads(ctx context.Context, eco, name string) (int, error)
	// Evidence returns the install-hook files of a package, read in memory.
	Evidence(ctx context.Context, eco string, info *PackageInfo) ([]EvidenceFile, error)
}

// HTTPRegistry queries registry.npmjs.org and pypi.org.
type HTTPRegistry struct {
	Client    *http.Client
	NPMBase   string
	PyPIBase  string
	NPMStats  string
	PyPIStats string
	// CratesBase and GemsBase are the crates.io and rubygems.org roots.
	CratesBase string
	GemsBase   string
	// AllowInsecureTarballs permits http:// tarball URLs (tests only).
	AllowInsecureTarballs bool

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	info *PackageInfo
	err  error
	at   time.Time
}

// NewHTTPRegistry returns a registry client with sane limits.
func NewHTTPRegistry() *HTTPRegistry {
	return &HTTPRegistry{
		Client:     &http.Client{Timeout: 10 * time.Second},
		NPMBase:    "https://registry.npmjs.org",
		PyPIBase:   "https://pypi.org",
		NPMStats:   "https://api.npmjs.org",
		PyPIStats:  "https://pypistats.org",
		CratesBase: "https://crates.io",
		GemsBase:   "https://rubygems.org",
		cache:      map[string]cached{},
	}
}

const maxPackument = 12 << 20

func (r *HTTPRegistry) get(ctx context.Context, u string, limit int64) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "pkgguard-bifrost-plugin")
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if int64(len(b)) > limit {
		return nil, resp.StatusCode, fmt.Errorf("response from %s larger than %d bytes", u, limit)
	}
	return b, resp.StatusCode, nil
}

// Lookup implements Registry.
func (r *HTTPRegistry) Lookup(ctx context.Context, eco, name, spec string) (*PackageInfo, error) {
	key := eco + "|" + name + "|" + spec
	r.mu.Lock()
	if c, ok := r.cache[key]; ok && time.Since(c.at) < 5*time.Minute {
		r.mu.Unlock()
		return c.info, c.err
	}
	r.mu.Unlock()

	var info *PackageInfo
	var err error
	switch eco {
	case "npm":
		info, err = r.lookupNPM(ctx, name, spec)
	case "pypi":
		info, err = r.lookupPyPI(ctx, name, spec)
	case "crates.io":
		info, err = r.lookupCrates(ctx, name, spec)
	case "rubygems":
		info, err = r.lookupRubyGems(ctx, name, spec)
	default:
		return nil, fmt.Errorf("no registry client for %s", eco)
	}
	r.mu.Lock()
	r.cache[key] = cached{info, err, time.Now()}
	r.mu.Unlock()
	return info, err
}

type npmPackument struct {
	DistTags map[string]string             `json:"dist-tags"`
	Time     map[string]string             `json:"time"`
	Versions map[string]npmVersionManifest `json:"versions"`
}

type npmVersionManifest struct {
	Scripts      map[string]string `json:"scripts"`
	Dependencies map[string]string `json:"dependencies"`
	GypFile      bool              `json:"gypfile"`
	Dist         struct {
		Tarball string `json:"tarball"`
	} `json:"dist"`
}

var exactVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.+-]+)?$`)

func (r *HTTPRegistry) lookupNPM(ctx context.Context, name, spec string) (*PackageInfo, error) {
	u := r.NPMBase + "/" + strings.Replace(url.PathEscape(name), "%40", "@", 1)
	body, code, err := r.get(ctx, u, maxPackument)
	if err != nil {
		return nil, err
	}
	switch code {
	case http.StatusNotFound:
		return &PackageInfo{Exists: false}, nil
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("npm registry returned HTTP %d for %s", code, name)
	}
	var pk npmPackument
	if err := json.Unmarshal(body, &pk); err != nil {
		return nil, fmt.Errorf("npm packument for %s: %w", name, err)
	}
	info := &PackageInfo{Exists: true, Versions: map[string]time.Time{}}
	for v := range pk.Versions {
		if t, err := time.Parse(time.RFC3339, pk.Time[v]); err == nil {
			info.Versions[v] = t
		}
	}
	if t, err := time.Parse(time.RFC3339, pk.Time["created"]); err == nil {
		info.Created = t
	}
	ver := strings.TrimPrefix(spec, "v")
	switch {
	case spec == "" || spec == "latest" || strings.ContainsAny(spec, "^~<>*| ") || strings.EqualFold(spec, "x"):
		ver = pk.DistTags["latest"]
	case pk.DistTags[spec] != "":
		ver = pk.DistTags[spec]
	case exactVersion.MatchString(spec):
		if _, ok := pk.Versions[ver]; !ok {
			info.VersionMissing = true
			info.Version = ver
			return info, nil
		}
	default:
		ver = pk.DistTags["latest"]
	}
	m, ok := pk.Versions[ver]
	if !ok {
		info.Version = ver
		return info, nil
	}
	info.Version = ver
	info.VersionPublished = info.Versions[ver]
	info.GypFile = m.GypFile
	info.TarballURL = m.Dist.Tarball
	info.Scripts = map[string]string{}
	for _, k := range []string{"preinstall", "install", "postinstall", "prepare", "prepublish"} {
		if s := m.Scripts[k]; s != "" {
			info.Scripts[k] = s
		}
	}
	for d := range m.Dependencies {
		info.Dependencies = append(info.Dependencies, d)
	}
	sort.Strings(info.Dependencies)
	return info, nil
}

type pypiDoc struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
	Releases map[string][]struct {
		UploadTime string `json:"upload_time_iso_8601"`
	} `json:"releases"`
}

var pyExact = regexp.MustCompile(`^==\s*(\d[\w.!+-]*)$`)

func (r *HTTPRegistry) lookupPyPI(ctx context.Context, name, spec string) (*PackageInfo, error) {
	body, code, err := r.get(ctx, r.PyPIBase+"/pypi/"+url.PathEscape(name)+"/json", maxPackument)
	if err != nil {
		return nil, err
	}
	switch code {
	case http.StatusNotFound:
		return &PackageInfo{Exists: false}, nil
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("PyPI returned HTTP %d for %s", code, name)
	}
	var d pypiDoc
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("PyPI document for %s: %w", name, err)
	}
	info := &PackageInfo{Exists: true, Versions: map[string]time.Time{}}
	for v, files := range d.Releases {
		for _, f := range files {
			t, err := time.Parse(time.RFC3339, f.UploadTime)
			if err != nil {
				t, err = time.Parse(time.RFC3339, f.UploadTime+"Z")
			}
			if err == nil && (info.Versions[v].IsZero() || t.Before(info.Versions[v])) {
				info.Versions[v] = t
			}
		}
		if t := info.Versions[v]; !t.IsZero() && (info.Created.IsZero() || t.Before(info.Created)) {
			info.Created = t
		}
	}
	ver := d.Info.Version
	if m := pyExact.FindStringSubmatch(spec); m != nil {
		ver = m[1]
		if _, ok := d.Releases[ver]; !ok {
			info.VersionMissing = true
			info.Version = ver
			return info, nil
		}
	}
	info.Version = ver
	info.VersionPublished = info.Versions[ver]
	return info, nil
}

// ---- tarball evidence (npm) -------------------------------------------------------

const (
	maxTarball       = 8 << 20
	maxEvidenceFile  = 6000
	maxEvidenceFiles = 4
)

var scriptFileRe = regexp.MustCompile(`[\w./@-]+\.(?:c?js|mjs|sh|py|ps1|bat|cmd)\b`)

// Evidence implements Registry: it downloads the npm tarball into memory and
// returns the files that the install-time scripts point at. Nothing is run.
func (r *HTTPRegistry) Evidence(ctx context.Context, eco string, info *PackageInfo) ([]EvidenceFile, error) {
	if eco != "npm" || info == nil || info.TarballURL == "" {
		return nil, nil
	}
	if !strings.HasPrefix(info.TarballURL, "https://") && !r.AllowInsecureTarballs {
		return nil, fmt.Errorf("refusing non-https tarball URL")
	}
	body, code, err := r.get(ctx, info.TarballURL, maxTarball)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("tarball HTTP %d", code)
	}
	return installFilesFromTarball(body, info)
}

func installFilesFromTarball(gz []byte, info *PackageInfo) ([]EvidenceFile, error) {
	want := map[string]bool{}
	for _, s := range info.Scripts {
		for _, m := range scriptFileRe.FindAllString(s, -1) {
			want[strings.TrimPrefix(strings.TrimPrefix(m, "./"), "package/")] = true
		}
	}
	if info.GypFile {
		want["binding.gyp"] = true
	}
	if len(want) == 0 {
		return nil, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	var files []EvidenceFile
	for len(files) < maxEvidenceFiles {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return files, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		rel := h.Name
		if i := strings.Index(rel, "/"); i >= 0 {
			rel = rel[i+1:] // drop the leading "package/"
		}
		if !want[rel] {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxEvidenceFile))
		if err != nil {
			return files, err
		}
		files = append(files, EvidenceFile{Path: rel, Content: string(b)})
	}
	return files, nil
}

// WeeklyDownloads implements Registry.
func (r *HTTPRegistry) WeeklyDownloads(ctx context.Context, eco, name string) (int, error) {
	var u string
	switch eco {
	case "npm":
		u = r.NPMStats + "/downloads/point/last-week/" + strings.Replace(url.PathEscape(name), "%40", "@", 1)
	case "pypi":
		u = r.PyPIStats + "/api/packages/" + url.PathEscape(name) + "/recent"
	case "crates.io":
		u = r.CratesBase + "/api/v1/crates/" + url.PathEscape(name)
	default:
		return 0, fmt.Errorf("no download stats for %s", eco)
	}
	body, code, err := r.get(ctx, u, 1<<20)
	if err != nil {
		return 0, err
	}
	if code != http.StatusOK {
		return 0, fmt.Errorf("download stats HTTP %d", code)
	}
	var out struct {
		Downloads int `json:"downloads"`
		Data      struct {
			LastWeek int `json:"last_week"`
		} `json:"data"`
		Crate struct {
			Recent int `json:"recent_downloads"` // last 90 days
		} `json:"crate"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, err
	}
	switch eco {
	case "pypi":
		return out.Data.LastWeek, nil
	case "crates.io":
		return out.Crate.Recent / 13, nil
	}
	return out.Downloads, nil
}

type cratesDoc struct {
	Crate struct {
		MaxVersion string `json:"max_stable_version"`
		NewestVer  string `json:"newest_version"`
		CreatedAt  string `json:"created_at"`
	} `json:"crate"`
	Versions []struct {
		Num       string `json:"num"`
		CreatedAt string `json:"created_at"`
		Yanked    bool   `json:"yanked"`
	} `json:"versions"`
}

func (r *HTTPRegistry) lookupCrates(ctx context.Context, name, spec string) (*PackageInfo, error) {
	body, code, err := r.get(ctx, r.CratesBase+"/api/v1/crates/"+url.PathEscape(name), maxPackument)
	if err != nil {
		return nil, err
	}
	switch code {
	case http.StatusNotFound:
		return &PackageInfo{Exists: false}, nil
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("crates.io returned HTTP %d for %s", code, name)
	}
	var d cratesDoc
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("crates.io document for %s: %w", name, err)
	}
	info := &PackageInfo{Exists: true, Versions: map[string]time.Time{}}
	info.Created, _ = time.Parse(time.RFC3339, d.Crate.CreatedAt)
	for _, v := range d.Versions {
		if t, err := time.Parse(time.RFC3339, v.CreatedAt); err == nil && !v.Yanked {
			info.Versions[v.Num] = t
		}
	}
	return finishVersion(info, firstNonEmpty(d.Crate.MaxVersion, d.Crate.NewestVer), spec), nil
}

func (r *HTTPRegistry) lookupRubyGems(ctx context.Context, name, spec string) (*PackageInfo, error) {
	body, code, err := r.get(ctx, r.GemsBase+"/api/v1/versions/"+url.PathEscape(name)+".json", maxPackument)
	if err != nil {
		return nil, err
	}
	switch code {
	case http.StatusNotFound:
		return &PackageInfo{Exists: false}, nil
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("rubygems.org returned HTTP %d for %s", code, name)
	}
	var vs []struct {
		Number     string `json:"number"`
		CreatedAt  string `json:"created_at"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.Unmarshal(body, &vs); err != nil {
		return nil, fmt.Errorf("rubygems document for %s: %w", name, err)
	}
	info := &PackageInfo{Exists: true, Versions: map[string]time.Time{}}
	latest := ""
	var latestT time.Time
	for _, v := range vs { // the API lists newest first
		t, err := time.Parse(time.RFC3339, v.CreatedAt)
		if err != nil {
			continue
		}
		info.Versions[v.Number] = t
		if info.Created.IsZero() || t.Before(info.Created) {
			info.Created = t
		}
		if !v.Prerelease && t.After(latestT) {
			latest, latestT = v.Number, t
		}
	}
	return finishVersion(info, latest, spec), nil
}

// finishVersion resolves the version a spec points at: exact if known, else the latest.
func finishVersion(info *PackageInfo, latest, spec string) *PackageInfo {
	ver := latest
	v := strings.TrimPrefix(strings.TrimPrefix(spec, "="), "v")
	if exactVersion.MatchString(v) {
		if _, ok := info.Versions[v]; !ok {
			info.VersionMissing = true
			info.Version = v
			return info
		}
		ver = v
	}
	info.Version = ver
	info.VersionPublished = info.Versions[ver]
	return info
}
