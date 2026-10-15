package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/daemon"
	"github.com/onek8s/azure-lab-fw/internal/logging"
	"github.com/onek8s/azure-lab-fw/internal/policy"
)

const defaultConfigPath = "/etc/labfw/config.yaml"

// runRun implements `labfw run --config f`: the daemon (systemd).
// SIGHUP triggers an immediate refresh; SIGTERM/SIGINT stop gracefully and
// leave the ruleset loaded unless dataplane.removeOnExit is set.
func runRun(args []string, _, stderr io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	logger := logging.NewSlogLogger(cfg.Logging.Level)
	slog.SetDefault(logger)
	d, err := daemon.New(cfg, daemon.Deps{Logger: logger, ConfigPath: *cfgPath})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-hup:
				d.TriggerRefresh()
			case <-ctx.Done():
				return
			}
		}
	}()
	logger.Info("labfw starting", "version", version, "commit", commit, "config", *cfgPath)
	return d.Run(ctx)
}

// runFetch implements `labfw fetch --config f [--out policy.json]`: download
// the policy chain, IP groups and referenced service tags in file-source
// format.
func runFetch(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfigPath, "config file (policy.*, azure.*)")
	out := fs.String("out", "-", "output file (- = stdout)")
	stateDir := fs.String("state-dir", "", "override stateDir (service tag cache)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *stateDir != "" {
		cfg.StateDir = *stateDir
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	b, err := fetchBundle(cfg, logger)
	if err != nil {
		return err
	}
	for _, w := range b.Warnings {
		fmt.Fprintln(stderr, "warning:", w.String())
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *out == "-" {
		_, err = stdout.Write(data)
		return err
	}
	return policy.WriteFileAtomic(*out, data, 0o644)
}

// fetchBundle fetches the bundle from the configured source.
func fetchBundle(cfg *config.Config, logger *slog.Logger) (*policy.Bundle, error) {
	if cfg.Policy.Source == "file" {
		return policy.NewFileSource(cfg.Policy.File).Fetch(context.Background())
	}
	az, err := daemon.NewAzureClient(cfg, logger)
	if err != nil && cfg.Policy.Source == "arm" {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	src, err := daemon.NewSource(cfg, az, logger)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return src.Fetch(ctx)
}
