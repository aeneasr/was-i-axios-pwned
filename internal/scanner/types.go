package scanner

import (
	"context"
	"io"
)

const DefaultSince = "2026-03-30T23:59:00Z"

type Verdict string

const (
	NoEvidence    Verdict = "NO_EVIDENCE"
	LikelyExposed Verdict = "LIKELY_EXPOSED"
	Confirmed     Verdict = "CONFIRMED"
)

type Coverage string

const (
	CoverageComplete Coverage = "COMPLETE"
	CoveragePartial  Coverage = "PARTIAL"
)

type WarningClass string

const (
	WarningCoverage  WarningClass = "COVERAGE"
	WarningRangeRisk WarningClass = "RANGE_RISK"
)

type Config struct {
	Since      string
	Deep       bool
	Roots      []string
	ReportDir  string
	Platform   string
	HomeDir    string
	WorkingDir string
	Env        map[string]string
}

type DefaultConfig struct {
	Platform   string
	HomeDir    string
	WorkingDir string
	Env        map[string]string
}

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type Finding struct {
	Severity  Verdict
	Source    string
	Indicator string
	Location  string
	Detail    string
}

type Warning struct {
	Class   WarningClass
	Message string
}

type RangeRisk struct {
	Manifest string
	Project  string
	Spec     string
	Versions []string
}

type RawSnippet struct {
	Title string
	Body  string
}

type Report struct {
	Verdict    Verdict
	Coverage   Coverage
	Platform   string
	Since      string
	Deep       bool
	Roots      []string
	Findings   []Finding
	Warnings   []Warning
	RangeRisks []RangeRisk
	Raw        map[string][]RawSnippet
}

type Runner interface {
	LookPath(name string) (string, error)
	CombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error)
}

type Option func(*options)

type options struct {
	runner    Runner
	defaults  DefaultConfig
	buildInfo BuildInfo
}

type cliWriters struct {
	stdout io.Writer
	stderr io.Writer
}
