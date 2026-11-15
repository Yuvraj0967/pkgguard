package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/pkgguard/pkgguard"
)

func runBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "")
	verbose := fs.Bool("v", false, "")
	fs.Usage = usage
	fs.Parse(args)

	systems, err := pkgguard.DefaultBenchSystems()
	if err != nil {
		fail("%v", err)
	}
	scenarios := pkgguard.BenchScenarios()
	var results []pkgguard.BenchResult
	for _, s := range systems {
		results = append(results, pkgguard.RunBench(context.Background(), s, scenarios))
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(results)
		return
	}
	fmt.Printf("red-team benchmark: %d labelled commands in a synthetic package world (deterministic, no network)\n\n", len(scenarios))
	fmt.Println(pkgguard.FormatBenchMarkdown(results))
	if *verbose {
		for _, r := range results {
			fmt.Printf("\n%s missed:\n", r.System)
			for _, m := range r.SortedMissed() {
				fmt.Println("  -", m)
			}
		}
	}
	last := results[len(results)-1]
	if last.FalseBlocks > 0 {
		fmt.Printf("\nfalse blocks (%s):\n", last.System)
		for _, c := range last.Categories {
			for _, w := range c.WronglyBlocked {
				fmt.Println("  -", w)
			}
		}
		os.Exit(2)
	}
}
