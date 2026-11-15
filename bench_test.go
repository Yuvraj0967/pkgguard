package pkgguard

import (
	"context"
	"testing"
)

// The benchmark is a regression gate: the numbers in the README must stay true.
func TestBenchmarkRegression(t *testing.T) {
	systems, err := DefaultBenchSystems()
	if err != nil {
		t.Fatal(err)
	}
	scenarios := BenchScenarios()
	byName := map[string]BenchResult{}
	for _, s := range systems {
		byName[s.Name] = RunBench(context.Background(), s, scenarios)
	}
	full := byName["pkgguard full"]
	if full.FalseBlocks != 0 {
		for _, c := range full.Categories {
			for _, w := range c.WronglyBlocked {
				t.Errorf("false block: %s", w)
			}
		}
	}
	if full.Recall() < 1.0 {
		t.Errorf("recall regressed to %.1f%%; missed: %v", 100*full.Recall(), full.SortedMissed())
	}
	if full.Warnings > 3 {
		t.Errorf("too much friction: %d benign commands warned", full.Warnings)
	}
	// the point of the project: the gateway-aware checks beat a blocklist by a wide margin
	if full.Recall() < byName["Blocklist only"].Recall()+0.5 {
		t.Errorf("pkgguard full (%.0f%%) must beat the blocklist (%.0f%%) by 50 points", 100*full.Recall(), 100*byName["Blocklist only"].Recall())
	}
	if full.GapTotal == 0 {
		t.Error("the known-gaps class must not be dropped")
	}
	if len(scenarios) < 100 {
		t.Errorf("corpus shrank to %d scenarios", len(scenarios))
	}
}
