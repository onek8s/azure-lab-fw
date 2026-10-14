// Command labfw emulates Azure Firewall on a small Linux VM (see docs/PLAN.md).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// Set by -ldflags at release time.
var (
	version = "dev"
	commit  = "none"
)

type command struct {
	name, usage string
	run         func(args []string, stdout, stderr io.Writer) error
}

var errUsage = errors.New("usage")

func commands() []command {
	return []command{
		{"run", "run the daemon", notImplemented("run")},
		{"fetch", "download policy in file-source format", notImplemented("fetch")},
		{"compile", "compile a policy and print ir|nft|diagnostics", notImplemented("compile")},
		{"explain", "explain the decision for a flow", notImplemented("explain")},
		{"nsg-rules", "print inbound NSG rules required for DNAT", notImplemented("nsg-rules")},
		{"ca", "TLS inspection CA (ca export)", notImplemented("ca")},
		{"fqdn-tags", "print the FQDN tag catalogue", runFQDNTags},
		{"version", "print version", func(_ []string, out, _ io.Writer) error {
			_, err := fmt.Fprintf(out, "labfw %s (%s)\n", version, commit)
			return err
		}},
	}
}

func notImplemented(name string) func([]string, io.Writer, io.Writer) error {
	return func([]string, io.Writer, io.Writer) error { return fmt.Errorf("%s: not implemented yet", name) }
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: labfw <command> [flags]\n\ncommands:")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.usage)
	}
}

func realMain(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		usage(stderr)
		return 2
	}
	for _, c := range commands() {
		if c.name == args[0] {
			if err := c.run(args[1:], stdout, stderr); err != nil {
				if errors.Is(err, flag.ErrHelp) || errors.Is(err, errUsage) {
					return 2
				}
				fmt.Fprintln(stderr, "labfw:", err)
				return 1
			}
			return 0
		}
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(stdout)
		return 0
	}
	fmt.Fprintf(stderr, "labfw: unknown command %q\n", args[0])
	usage(stderr)
	return 2
}

func main() { os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr)) }
