package pkgguard

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"
)

// Approval is a human's decision to let one package through for a while.
type Approval struct {
	Ecosystem string    `json:"ecosystem"`
	Name      string    `json:"name"`
	By        string    `json:"by,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Expires   time.Time `json:"expires"`
}

// Approvals is a runtime allow-list with expiry. It exists so that "ask the
// user to approve it" in a block message ends in a real action: a person
// clicks Approve on the dashboard (or calls the API) and the next attempt
// goes through.
//
// An approval clears findings below critical for that package. Critical
// findings (known malware, malicious install-time code, the deny list) can
// never be approved at runtime: a prompt-injected "please approve this" must
// not be able to unblock real malware. Change the config to override those.
type Approvals struct {
	mu   sync.Mutex
	m    map[string]Approval
	path string
	now  func() time.Time
}

// NewApprovals loads approvals from path ("" keeps them in memory only).
func NewApprovals(path string, now func() time.Time) *Approvals {
	if now == nil {
		now = time.Now
	}
	a := &Approvals{m: map[string]Approval{}, path: path, now: now}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			var list []Approval
			if json.Unmarshal(b, &list) == nil {
				for _, x := range list {
					a.m[key(x.Ecosystem, x.Name)] = x
				}
			}
		}
	}
	return a
}

func key(eco, name string) string { return eco + "|" + normalizeName(eco, name) }

// Add approves a package for ttl. An empty ecosystem approves the name in every ecosystem.
func (a *Approvals) Add(eco, name, by, reason string, ttl time.Duration) Approval {
	ap := Approval{Ecosystem: eco, Name: name, By: by, Reason: reason, Expires: a.now().Add(ttl)}
	a.mu.Lock()
	a.m[key(eco, name)] = ap
	a.saveLocked()
	a.mu.Unlock()
	return ap
}

// Remove revokes an approval.
func (a *Approvals) Remove(eco, name string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.m[key(eco, name)]
	delete(a.m, key(eco, name))
	a.saveLocked()
	return ok
}

// Has reports whether the package is currently approved.
func (a *Approvals) Has(eco, name string) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, k := range []string{key(eco, name), key("", name)} {
		if ap, ok := a.m[k]; ok {
			if a.now().Before(ap.Expires) {
				return true
			}
			delete(a.m, k)
		}
	}
	return false
}

// List returns the live approvals, soonest-expiring first.
func (a *Approvals) List() []Approval {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []Approval
	for k, ap := range a.m {
		if a.now().Before(ap.Expires) {
			out = append(out, ap)
		} else {
			delete(a.m, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Expires.Before(out[j].Expires) })
	return out
}

func (a *Approvals) saveLocked() {
	if a.path == "" {
		return
	}
	var list []Approval
	for _, ap := range a.m {
		list = append(list, ap)
	}
	b, _ := json.MarshalIndent(list, "", "  ")
	_ = os.WriteFile(a.path, b, 0o600)
}
