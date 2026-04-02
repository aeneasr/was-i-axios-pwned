package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type stubCommandResult struct {
	output string
	err    error
}

type stubRunner struct {
	lookups map[string]bool
	outputs map[string]stubCommandResult
}

func (r stubRunner) LookPath(name string) (string, error) {
	if r.lookups[name] {
		return "/stub/" + name, nil
	}
	return "", fmt.Errorf("missing command: %s", name)
}

func (r stubRunner) CombinedOutput(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + "\x00" + strings.Join(args, "\x00")
	if result, ok := r.outputs[key]; ok {
		return []byte(result.output), result.err
	}
	return nil, fmt.Errorf("unexpected command: %s %s", name, strings.Join(args, " "))
}

func writeFixture(t *testing.T, root, rel, contents string) string {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func newTestConfig(root string) Config {
	return Config{
		Since:      DefaultSince,
		Roots:      []string{root},
		Platform:   "linux",
		HomeDir:    root,
		WorkingDir: root,
		Env: map[string]string{
			"HOME":        root,
			"TMPDIR":      filepath.Join(root, "tmp"),
			"ProgramData": filepath.Join(root, "ProgramData"),
			"TEMP":        filepath.Join(root, "Temp"),
		},
	}
}

func TestRunWarnsForSemverRangeWithoutDirectEvidence(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "package.json", `{
  "dependencies": {
    "axios": "^1.14.0"
  }
}`)

	scanner := New(newTestConfig(root), WithRunner(stubRunner{}))
	report, err := scanner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if report.Verdict != NoEvidence {
		t.Fatalf("verdict = %s, want %s", report.Verdict, NoEvidence)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(report.Findings))
	}
	if len(report.RangeRisks) != 1 {
		t.Fatalf("range risks = %d, want 1", len(report.RangeRisks))
	}
	if got := report.RangeRisks[0].Versions; len(got) != 1 || got[0] != "1.14.1" {
		t.Fatalf("range risk versions = %v, want [1.14.1]", got)
	}
}

func TestRunSuppressesRangeRiskWhenProjectHasDirectEvidence(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "package.json", `{
  "dependencies": {
    "axios": "^1.14.0"
  }
}`)
	writeFixture(t, root, "package-lock.json", `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "dependencies": {
        "axios": "^1.14.0"
      }
    },
    "node_modules/axios": {
      "version": "1.14.1",
      "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz",
      "integrity": "sha512-deadbeef"
    }
  }
}`)

	scanner := New(newTestConfig(root), WithRunner(stubRunner{}))
	report, err := scanner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if report.Verdict != LikelyExposed {
		t.Fatalf("verdict = %s, want %s", report.Verdict, LikelyExposed)
	}
	if len(report.Findings) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	if len(report.RangeRisks) != 0 {
		t.Fatalf("range risks = %d, want 0", len(report.RangeRisks))
	}
}

func TestRunConfirmsPlainCryptoResidueAndHiddenLockfile(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "node_modules/.package-lock.json", `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/plain-crypto-js": {
      "version": "4.2.1",
      "resolved": "https://registry.npmjs.org/plain-crypto-js/-/plain-crypto-js-4.2.1.tgz",
      "integrity": "sha512-plain",
      "hasInstallScript": true
    }
  }
}`)
	writeFixture(t, root, "node_modules/plain-crypto-js/package.json", `{
  "name": "plain-crypto-js",
  "version": "4.2.0",
  "main": "index.js"
}`)
	writeFixture(t, root, "node_modules/plain-crypto-js/package.md", `{
  "name": "plain-crypto-js",
  "version": "4.2.0"
}`)

	scanner := New(newTestConfig(root), WithRunner(stubRunner{}))
	report, err := scanner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if report.Verdict != Confirmed {
		t.Fatalf("verdict = %s, want %s", report.Verdict, Confirmed)
	}
	if !containsIndicator(report.Findings, "plain-crypto-js") {
		t.Fatalf("findings do not include plain-crypto-js directory evidence: %#v", report.Findings)
	}
	if !containsIndicator(report.Findings, "plain-crypto-js fake 4.2.0 manifest") {
		t.Fatalf("findings do not include fake 4.2.0 manifest evidence: %#v", report.Findings)
	}
}

func TestRunDetectsWindowsArtifacts(t *testing.T) {
	root := t.TempDir()
	programData := filepath.Join(root, "ProgramData")
	tempDir := filepath.Join(root, "Temp")
	writeFixture(t, programData, "wt.exe", "binary")
	writeFixture(t, tempDir, "6202033.ps1", "payload")
	writeFixture(t, tempDir, "6202033.vbs", "payload")

	cfg := newTestConfig(root)
	cfg.Platform = "windows"
	cfg.Env["ProgramData"] = programData
	cfg.Env["TEMP"] = tempDir

	scanner := New(cfg, WithRunner(stubRunner{}))
	report, err := scanner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if report.Verdict != Confirmed {
		t.Fatalf("verdict = %s, want %s", report.Verdict, Confirmed)
	}
	if !containsLocation(report.Findings, filepath.Join(programData, "wt.exe")) {
		t.Fatalf("expected ProgramData wt.exe finding, got %#v", report.Findings)
	}
}

func TestCLIWritesReportBundleAndDoesNotEscalateRangeRiskExitCode(t *testing.T) {
	root := t.TempDir()
	reportDir := filepath.Join(root, "report")
	writeFixture(t, root, "package.json", `{
  "dependencies": {
    "axios": ">=1.14.0 <1.14.2"
  }
}`)

	var stdout, stderr bytes.Buffer
	exitCode := RunCLI(
		context.Background(),
		[]string{"--roots", root, "--report-dir", reportDir},
		&stdout,
		&stderr,
		WithRunner(stubRunner{}),
		WithDefaultConfig(DefaultConfig{
			Platform:   "linux",
			WorkingDir: root,
			HomeDir:    root,
			Env: map[string]string{
				"HOME":        root,
				"TMPDIR":      filepath.Join(root, "tmp"),
				"ProgramData": filepath.Join(root, "ProgramData"),
				"TEMP":        filepath.Join(root, "Temp"),
			},
		}),
	)

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	summary, err := os.ReadFile(filepath.Join(reportDir, "summary.txt"))
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if !strings.Contains(string(summary), "Potential Range Risks") {
		t.Fatalf("summary missing range risk section:\n%s", summary)
	}
	warnings, err := os.ReadFile(filepath.Join(reportDir, "warnings.txt"))
	if err != nil {
		t.Fatalf("read warnings: %v", err)
	}
	if !strings.Contains(string(warnings), "RANGE_RISK") {
		t.Fatalf("warnings missing RANGE_RISK entry:\n%s", warnings)
	}
}

func TestCLIVersionFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := RunCLI(
		context.Background(),
		[]string{"--version"},
		&stdout,
		&stderr,
		WithBuildInfo(BuildInfo{
			Version: "0.1.0",
			Commit:  "abc1234",
			Date:    "2026-04-02T10:00:00Z",
		}),
	)

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "was-i-axios-pwned 0.1.0 (commit abc1234, built 2026-04-02T10:00:00Z)") {
		t.Fatalf("stdout = %q, want version metadata", got)
	}
}

func TestPrepareTargetsDeepUnixUsesFilesystemRoot(t *testing.T) {
	root := t.TempDir()
	cfg := newTestConfig(root)
	cfg.Deep = true

	scanner := New(cfg, WithRunner(stubRunner{}))
	state := &scanState{
		report: Report{
			Raw: map[string][]RawSnippet{},
		},
	}
	if err := scanner.prepareTargets(context.Background(), state); err != nil {
		t.Fatalf("prepareTargets() error = %v", err)
	}

	if len(state.report.Roots) != 1 || state.report.Roots[0] != string(os.PathSeparator) {
		t.Fatalf("roots = %#v, want [\"/\"]", state.report.Roots)
	}
}

func TestPruneNestedRoots(t *testing.T) {
	roots := pruneNestedRoots([]string{
		"/Users/aeneas/workspace",
		"/",
		"/Users/aeneas",
		"/opt/builds",
	})

	if len(roots) != 1 || roots[0] != "/" {
		t.Fatalf("roots = %#v, want [\"/\"]", roots)
	}
}

func containsIndicator(findings []Finding, indicator string) bool {
	for _, finding := range findings {
		if finding.Indicator == indicator {
			return true
		}
	}
	return false
}

func containsLocation(findings []Finding, location string) bool {
	for _, finding := range findings {
		if finding.Location == location {
			return true
		}
	}
	return false
}
