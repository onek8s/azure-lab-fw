package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/fqdn"
)

// runFQDNTags implements `labfw fqdn-tags [--config f] [--office365] [--tag X]`.
func runFQDNTags(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("fqdn-tags", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tag := fs.String("tag", "", "print the patterns one tag expands to")
	cfgPath := fs.String("config", "", "config file (uses fqdnTags.catalogue/extra/office365 and stateDir)")
	o365 := fs.Bool("office365", false, "also resolve Office365.* tags from endpoints.office.com (implied by --config with fqdnTags.office365)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}

	useCatalogue := true
	var extra map[string][]string
	cachePath := ""
	if *cfgPath != "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		useCatalogue = cfg.FQDNTags.Catalogue
		extra = cfg.FQDNTags.Extra
		*o365 = *o365 || cfg.FQDNTags.Office365
		cachePath = filepath.Join(cfg.StateDir, "o365-endpoints.json")
	} else if dir, err := os.UserCacheDir(); err == nil {
		cachePath = filepath.Join(dir, "labfw", "o365-endpoints.json")
	}
	var provider fqdn.O365Provider
	if *o365 {
		provider = fqdn.NewO365Client(cachePath)
	}
	e, err := fqdn.NewTagExpander(useCatalogue, extra, provider)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if *tag != "" {
		pats, err := e.ExpandContext(ctx, *tag)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "# %s (%s, %d patterns)\n", *tag, e.Source(*tag), len(pats))
		for _, p := range pats {
			fmt.Fprintln(stdout, fqdn.FormatFQDNPattern(p))
		}
		return nil
	}

	type row struct {
		name, source string
		n            int
	}
	var rows []row
	for _, t := range e.StaticTags() {
		rows = append(rows, row{t.Name, t.Source, len(t.Patterns)})
	}
	if provider != nil {
		tags, err := provider.Tags(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "labfw: warning:", err)
		}
		for name, pats := range tags {
			if e.Source(name) == "extra" {
				continue // overridden by fqdnTags.extra, already listed
			}
			rows = append(rows, row{name, "office365", len(pats)})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return strings.ToLower(rows[i].name) < strings.ToLower(rows[j].name) })
	fmt.Fprintf(stdout, "%-45s %-10s %s\n", "TAG", "SOURCE", "PATTERNS")
	for _, r := range rows {
		fmt.Fprintf(stdout, "%-45s %-10s %d\n", r.name, r.source, r.n)
	}
	return nil
}
