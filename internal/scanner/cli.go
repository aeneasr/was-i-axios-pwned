package scanner

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

func WithRunner(r Runner) Option {
	return func(opts *options) {
		opts.runner = r
	}
}

func WithDefaultConfig(cfg DefaultConfig) Option {
	return func(opts *options) {
		opts.defaults = cfg
	}
}

func WithBuildInfo(info BuildInfo) Option {
	return func(opts *options) {
		opts.buildInfo = info
	}
}

func RunCLI(ctx context.Context, args []string, stdout, stderr io.Writer, opts ...Option) int {
	parsedOpts := collectOptions(opts...)

	flags := flag.NewFlagSet("was-i-axios-pwned", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		since     = flags.String("since", DefaultSince, "")
		deep      = flags.Bool("deep", false, "")
		rootsSpec = flags.String("roots", "", "")
		reportDir = flags.String("report-dir", "", "")
		showVer   = flags.Bool("version", false, "")
	)

	flags.Usage = func() {
		fmt.Fprintf(stdout, "Usage: was-i-axios-pwned [--since ISO8601] [--deep] [--roots path1,path2] [--report-dir PATH]\n\n")
		fmt.Fprintf(stdout, "Read-only host triage for the malicious axios npm releases published on 2026-03-31.\n\n")
		fmt.Fprintf(stdout, "Options:\n")
		fmt.Fprintf(stdout, "  --since ISO8601     Start time for log collectors. Default: %s\n", DefaultSince)
		fmt.Fprintf(stdout, "  --deep              Expand scanning to filesystem roots and wider system log coverage.\n")
		fmt.Fprintf(stdout, "  --roots CSV         Comma-separated project roots to scan in addition to the defaults.\n")
		fmt.Fprintf(stdout, "  --report-dir PATH   Write summary.txt, findings.tsv, warnings.txt, and raw snippets here.\n")
		fmt.Fprintf(stdout, "  --version           Print build version metadata.\n")
		fmt.Fprintf(stdout, "  --help              Show this message.\n")
	}

	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			flags.Usage()
			return 0
		}
		fmt.Fprintf(stderr, "Fatal: %s\n", err)
		return 3
	}

	if *showVer {
		fmt.Fprintf(stdout, "was-i-axios-pwned %s (commit %s, built %s)\n",
			defaultBuildValue(parsedOpts.buildInfo.Version, "dev"),
			defaultBuildValue(parsedOpts.buildInfo.Commit, "none"),
			defaultBuildValue(parsedOpts.buildInfo.Date, "unknown"),
		)
		return 0
	}

	cfg := Config{
		Since:      *since,
		Deep:       *deep,
		Roots:      splitCSV(*rootsSpec),
		ReportDir:  *reportDir,
		Platform:   firstNonEmpty(parsedOpts.defaults.Platform, runtime.GOOS),
		HomeDir:    parsedOpts.defaults.HomeDir,
		WorkingDir: parsedOpts.defaults.WorkingDir,
		Env:        cloneEnv(parsedOpts.defaults.Env),
	}

	if cfg.HomeDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cfg.HomeDir = home
		}
	}
	if cfg.WorkingDir == "" {
		if wd, err := os.Getwd(); err == nil {
			cfg.WorkingDir = wd
		}
	}
	if len(cfg.Env) == 0 {
		cfg.Env = currentEnv()
	}

	scanner := New(cfg, opts...)
	report, err := scanner.Run(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "Fatal: %s\n", err)
		return 3
	}

	summary := BuildSummary(report)
	_, _ = io.WriteString(stdout, summary)

	if cfg.ReportDir != "" {
		if err := WriteReportBundle(cfg.ReportDir, report, summary); err != nil {
			fmt.Fprintf(stderr, "Fatal: %s\n", err)
			return 3
		}
	}

	switch {
	case report.Verdict == Confirmed:
		return 2
	case report.Verdict == LikelyExposed || report.Coverage == CoveragePartial:
		return 1
	default:
		return 0
	}
}

func defaultBuildValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func collectOptions(opts ...Option) options {
	collected := options{}
	for _, opt := range opts {
		opt(&collected)
	}
	return collected
}

func splitCSV(spec string) []string {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	var parts []string
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parts = append(parts, part)
	}
	return parts
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func currentEnv() map[string]string {
	env := map[string]string{}
	for _, pair := range os.Environ() {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		env[key] = value
	}
	return env
}

func cloneEnv(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}
