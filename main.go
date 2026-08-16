// Command dep-vuln-scanner parses a dependency lock file, generates an SBOM
// and reports known vulnerabilities against a built-in advisory database.
package main

import (
	"flag"
	"fmt"
	"os"

	"dep-vuln-scanner/internal/manifest"
	"dep-vuln-scanner/internal/sbom"
	"dep-vuln-scanner/internal/vulndb"
)

func main() {
	manifestPath := flag.String("manifest", "dependencies.lock", "path to the dependency lock file")
	format := flag.String("format", "report", "output format: report | sbom")
	flag.Parse()

	f, err := os.Open(*manifestPath)
	if err != nil {
		fatal("open manifest: %v", err)
	}
	defer f.Close()

	deps, err := manifest.Parse(f)
	if err != nil {
		fatal("parse manifest: %v", err)
	}

	switch *format {
	case "sbom":
		doc := sbom.Generate(deps)
		out, err := doc.JSON()
		if err != nil {
			fatal("marshal sbom: %v", err)
		}
		fmt.Println(string(out))
	case "report":
		printReport(deps)
	default:
		fatal("unknown format %q (want report|sbom)", *format)
	}
}

func printReport(deps []manifest.Dependency) {
	db := vulndb.DefaultDB()
	total := 0
	fmt.Printf("Scanned %d dependencies\n\n", len(deps))
	for _, d := range deps {
		hits := db.Vulnerabilities(d.Name, d.Version)
		if len(hits) == 0 {
			continue
		}
		total += len(hits)
		fmt.Printf("[%s] %s @ %s\n", sevOf(hits), d.Name, d.Version)
		for _, h := range hits {
			fmt.Printf("    %s (%s): %s\n", h.ID, h.Severity, h.Summary)
		}
	}
	if total == 0 {
		fmt.Println("No known vulnerabilities found.")
	} else {
		fmt.Printf("\n%d vulnerability(ies) found.\n", total)
	}
}

func sevOf(hits []vulndb.Entry) string {
	worst := "low"
	order := map[string]int{"low": 0, "moderate": 1, "high": 2, "critical": 3}
	for _, h := range hits {
		if order[h.Severity] > order[worst] {
			worst = h.Severity
		}
	}
	return worst
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "dep-vuln-scanner: "+format+"\n", args...)
	os.Exit(1)
}
