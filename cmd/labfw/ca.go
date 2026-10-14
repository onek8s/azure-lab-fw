package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/certs"
	"github.com/onek8s/azure-lab-fw/internal/config"
)

// runCA implements `labfw ca export [--config f] [--state-dir d]`: print the
// TLS-inspection CA certificate (PEM) per the precedence of PLAN §6.7.
// Key Vault (source 1) is not consulted here (no Azure client in the CLI
// yet); the daemon uses it when the policy references one.
func runCA(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "export" {
		fmt.Fprintln(stderr, "usage: labfw ca export [--config file] [--state-dir dir]")
		return errUsage
	}
	fs := flag.NewFlagSet("ca export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "config file (appProxy.tls.* and stateDir)")
	stateDir := fs.String("state-dir", "", "override stateDir (local CA location)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	cfg := config.Default()
	if *cfgPath != "" {
		c, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		cfg = *c
	}
	if *stateDir != "" {
		cfg.StateDir = *stateDir
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca, err := certs.LoadCA(ctx, certs.LoadOptions{
		CAFile:          cfg.AppProxy.TLS.CAFile,
		CAKeyFile:       cfg.AppProxy.TLS.CAKeyFile,
		GenerateLocalCA: cfg.AppProxy.TLS.GenerateLocalCA,
		StateDir:        cfg.StateDir,
		Logger:          slog.New(slog.NewTextHandler(stderr, nil)),
	})
	if err != nil {
		return err
	}
	_, err = stdout.Write(ca.CertPEM())
	return err
}
