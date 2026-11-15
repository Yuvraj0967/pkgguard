package pkgguard

import (
	"context"
	"strings"
	"time"
)

// SimNow is the fixed clock of the simulated world used by the benchmark and the demo.
var SimNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

// SimPackage is one package in the simulated registry.
type SimPackage struct {
	Info      PackageInfo
	Downloads int
	Files     []EvidenceFile // install-hook files returned by Evidence
}

// SimRegistry is an in-memory Registry. It lets the benchmark, the demo and
// tests run deterministically with no network.
type SimRegistry struct {
	Pkgs map[string]*SimPackage // "ecosystem|name"
}

// Lookup implements Registry.
func (s *SimRegistry) Lookup(_ context.Context, eco, name, spec string) (*PackageInfo, error) {
	p, ok := s.Pkgs[eco+"|"+normalizeName(eco, name)]
	if !ok {
		return &PackageInfo{Exists: false}, nil
	}
	info := p.Info
	if v := strings.TrimPrefix(spec, "=="); v != "" {
		if t, ok := info.Versions[v]; ok {
			info.Version, info.VersionPublished = v, t
		}
	}
	return &info, nil
}

// WeeklyDownloads implements Registry.
func (s *SimRegistry) WeeklyDownloads(_ context.Context, eco, name string) (int, error) {
	if p, ok := s.Pkgs[eco+"|"+normalizeName(eco, name)]; ok {
		return p.Downloads, nil
	}
	return 0, nil
}

// Evidence implements Registry.
func (s *SimRegistry) Evidence(_ context.Context, eco string, info *PackageInfo) ([]EvidenceFile, error) {
	for k, p := range s.Pkgs {
		if strings.HasPrefix(k, eco+"|") && p.Info.TarballURL != "" && p.Info.TarballURL == info.TarballURL {
			return p.Files, nil
		}
	}
	return nil, nil
}

// SimMalware is an in-memory MalwareIndex keyed "ecosystem|name@version", or
// "ecosystem|name" for every version.
type SimMalware map[string][]string

// Malware implements MalwareIndex.
func (m SimMalware) Malware(_ context.Context, eco, name, version string) ([]string, error) {
	if ids, ok := m[eco+"|"+name+"@"+strings.TrimPrefix(version, "==")]; ok {
		return ids, nil
	}
	return m[eco+"|"+name], nil
}

// MalwareBatch implements BatchMalwareIndex.
func (m SimMalware) MalwareBatch(ctx context.Context, qs []BatchQuery) ([][]string, error) {
	out := make([][]string, len(qs))
	for i, q := range qs {
		out[i], _ = m.Malware(ctx, q.Eco, q.Name, q.Version)
	}
	return out, nil
}

// ---- builders ---------------------------------------------------------------------------

func daysAgo(d float64) time.Time { return SimNow.Add(-time.Duration(d * 24 * float64(time.Hour))) }

// SimEstablished returns a normal, well-used package.
func SimEstablished(version string, deps ...string) *SimPackage {
	return &SimPackage{Downloads: 2_000_000, Info: PackageInfo{
		Exists: true, Version: version, Created: daysAgo(2500), VersionPublished: daysAgo(60),
		Versions: map[string]time.Time{version: daysAgo(60)}, Dependencies: deps,
	}}
}

// SimWithInstall returns an established package whose install hook runs the given files.
func SimWithInstall(name, version, script string, files ...EvidenceFile) *SimPackage {
	p := SimEstablished(version)
	p.Info.Scripts = map[string]string{"postinstall": script}
	p.Info.TarballURL = "https://sim.invalid/" + name + "/" + version
	p.Files = files
	return p
}

// SimYoung returns a package first published `days` ago with few downloads.
func SimYoung(version string, days float64, downloads int) *SimPackage {
	return &SimPackage{Downloads: downloads, Info: PackageInfo{
		Exists: true, Version: version, Created: daysAgo(days), VersionPublished: daysAgo(days),
		Versions: map[string]time.Time{version: daysAgo(days)},
	}}
}
