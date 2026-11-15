package pkgguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// looseVersion matches a concrete version (1.2.3, 2.0, 1.0.0rc1, 2024.1.5), not a range or tag.
var looseVersion = regexp.MustCompile(`^v?[0-9][0-9A-Za-z.+!_-]*$`)

// MalwareIndex answers "is this package known malware?".
type MalwareIndex interface {
	// Malware returns the advisory IDs (MAL-..., GHSA-... malware) listed for the package.
	Malware(ctx context.Context, eco, name, version string) ([]string, error)
}

// OSV asks api.osv.dev. Only the package name, ecosystem and (optionally) the
// version leave the machine. Malware reports in OSV have IDs starting "MAL-".
type OSV struct {
	Client *http.Client
	Base   string

	mu    sync.Mutex
	cache map[string]osvCached
}

type osvCached struct {
	ids []string
	err error
	at  time.Time
}

// NewOSV returns an OSV client.
func NewOSV() *OSV {
	return &OSV{Client: &http.Client{Timeout: 8 * time.Second}, Base: "https://api.osv.dev", cache: map[string]osvCached{}}
}

var osvEcosystem = map[string]string{"npm": "npm", "pypi": "PyPI", "crates.io": "crates.io", "go": "Go", "rubygems": "RubyGems"}

// Malware implements MalwareIndex.
func (o *OSV) Malware(ctx context.Context, eco, name, version string) ([]string, error) {
	oe, ok := osvEcosystem[eco]
	if !ok {
		return nil, nil
	}
	key := eco + "|" + name + "|" + version
	o.mu.Lock()
	if c, ok := o.cache[key]; ok && time.Since(c.at) < 10*time.Minute {
		o.mu.Unlock()
		return c.ids, c.err
	}
	o.mu.Unlock()

	q := map[string]any{"package": map[string]string{"name": name, "ecosystem": oe}}
	if version != "" && looseVersion.MatchString(version) {
		q["version"] = strings.TrimPrefix(version, "v")
	}
	payload, _ := json.Marshal(q)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.Base+"/v1/query", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.Client.Do(req)
	var ids []string
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("OSV returned HTTP %d", resp.StatusCode)
		} else {
			var out struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			}
			if derr := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); derr != nil {
				err = derr
			}
			for _, v := range out.Vulns {
				if strings.HasPrefix(v.ID, "MAL-") {
					ids = append(ids, v.ID)
				}
			}
		}
	}
	o.mu.Lock()
	o.cache[key] = osvCached{ids, err, time.Now()}
	o.mu.Unlock()
	return ids, err
}

// MalwareBatch implements BatchMalwareIndex using OSV's /v1/querybatch (1000 queries per request).
func (o *OSV) MalwareBatch(ctx context.Context, qs []BatchQuery) ([][]string, error) {
	out := make([][]string, len(qs))
	const chunk = 1000
	for start := 0; start < len(qs); start += chunk {
		end := min(start+chunk, len(qs))
		var queries []map[string]any
		var pos []int
		for i := start; i < end; i++ {
			oe, ok := osvEcosystem[qs[i].Eco]
			if !ok {
				continue
			}
			q := map[string]any{"package": map[string]string{"name": qs[i].Name, "ecosystem": oe}}
			if v := strings.TrimPrefix(qs[i].Version, "v"); v != "" && looseVersion.MatchString(v) {
				q["version"] = v
			}
			queries = append(queries, q)
			pos = append(pos, i)
		}
		if len(queries) == 0 {
			continue
		}
		payload, _ := json.Marshal(map[string]any{"queries": queries})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.Base+"/v1/querybatch", bytes.NewReader(payload))
		if err != nil {
			return out, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := o.Client.Do(req)
		if err != nil {
			return out, err
		}
		var body struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		derr := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return out, fmt.Errorf("OSV returned HTTP %d", resp.StatusCode)
		}
		if derr != nil {
			return out, derr
		}
		for k, r := range body.Results {
			if k >= len(pos) {
				break
			}
			for _, v := range r.Vulns {
				if strings.HasPrefix(v.ID, "MAL-") {
					out[pos[k]] = append(out[pos[k]], v.ID)
				}
			}
		}
	}
	return out, nil
}
