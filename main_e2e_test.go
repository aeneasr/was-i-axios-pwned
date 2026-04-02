package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

type e2eResult struct {
	exitCode   int
	stdout     string
	stderr     string
	summary    string
	findings   string
	warnings   string
	reportDir  string
	rawDirPath string
}

func TestGoRunFixtures(t *testing.T) {
	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("resolve go binary: %v", err)
	}
	if !filepath.IsAbs(goBinary) {
		goBinary, err = filepath.Abs(goBinary)
		if err != nil {
			t.Fatalf("abs go binary: %v", err)
		}
	}

	goModCache, err := goEnv(goBinary, repoRoot, "GOMODCACHE")
	if err != nil {
		t.Fatalf("resolve GOMODCACHE: %v", err)
	}
	goPath, err := goEnv(goBinary, repoRoot, "GOPATH")
	if err != nil {
		t.Fatalf("resolve GOPATH: %v", err)
	}

	binary := buildBinary(t, goBinary, repoRoot)

	cases := []struct {
		name             string
		fixture          string
		wantExitCode     int
		wantSummary      []string
		wantFindings     []string
		wantWarnings     []string
		wantNoFindings   bool
		wantNoWarnings   bool
		noWarningSubstrs []string
	}{
		{
			name:           "no_evidence_empty_root",
			fixture:        "no_evidence_empty_root",
			wantExitCode:   0,
			wantSummary:    []string{"Verdict: NO_EVIDENCE", "Coverage: COMPLETE"},
			wantNoFindings: true,
			wantNoWarnings: true,
		},
		{
			name:           "manifest_range_risk",
			fixture:        "manifest_range_risk",
			wantExitCode:   0,
			wantSummary:    []string{"Verdict: NO_EVIDENCE", "Coverage: COMPLETE", "Potential Range Risks"},
			wantWarnings:   []string{"RANGE_RISK", "allows axios ^1.14.0", "1.14.1"},
			wantNoFindings: true,
		},
		{
			name:             "manifest_exact_compromised",
			fixture:          "manifest_exact_compromised",
			wantExitCode:     1,
			wantSummary:      []string{"Verdict: LIKELY_EXPOSED", "Coverage: COMPLETE"},
			wantFindings:     []string{"LIKELY_EXPOSED\tmanifest\taxios@1.14.1 reference"},
			noWarningSubstrs: []string{"RANGE_RISK"},
		},
		{
			name:             "npm_package_lock_compromised",
			fixture:          "npm_package_lock_compromised",
			wantExitCode:     1,
			wantSummary:      []string{"Verdict: LIKELY_EXPOSED", "Coverage: COMPLETE"},
			wantFindings:     []string{"LIKELY_EXPOSED\tlockfile\taxios@1.14.1 reference"},
			noWarningSubstrs: []string{"RANGE_RISK"},
		},
		{
			name:         "hidden_npm_lock_confirmed",
			fixture:      "hidden_npm_lock_confirmed",
			wantExitCode: 2,
			wantSummary:  []string{"Verdict: CONFIRMED", "Coverage: COMPLETE"},
			wantFindings: []string{"CONFIRMED\tpackage_directory\tplain-crypto-js", "CONFIRMED\tmanifest_swap\tplain-crypto-js fake 4.2.0 manifest"},
		},
		{
			name:         "yarn_lock_compromised",
			fixture:      "yarn_lock_compromised",
			wantExitCode: 1,
			wantSummary:  []string{"Verdict: LIKELY_EXPOSED", "Coverage: COMPLETE"},
			wantFindings: []string{"LIKELY_EXPOSED\tlockfile\taxios@1.14.1 reference"},
		},
		{
			name:         "pnpm_lock_compromised",
			fixture:      "pnpm_lock_compromised",
			wantExitCode: 1,
			wantSummary:  []string{"Verdict: LIKELY_EXPOSED", "Coverage: COMPLETE"},
			wantFindings: []string{"LIKELY_EXPOSED\tlockfile\taxios@1.14.1 reference"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := runFixtureE2E(t, repoRoot, binary, goModCache, goPath, tc.fixture)

			if result.exitCode != tc.wantExitCode {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", result.exitCode, tc.wantExitCode, result.stdout, result.stderr)
			}

			for _, want := range tc.wantSummary {
				if !strings.Contains(normalizeText(result.summary), normalizeText(want)) {
					t.Fatalf("summary missing %q\nsummary:\n%s", want, result.summary)
				}
			}

			if tc.wantNoFindings && strings.TrimSpace(result.findings) != "" {
				t.Fatalf("findings.tsv not empty:\n%s", result.findings)
			}
			for _, want := range tc.wantFindings {
				if !strings.Contains(normalizeText(result.findings), normalizeText(want)) {
					t.Fatalf("findings.tsv missing %q\nfindings:\n%s", want, result.findings)
				}
			}

			if tc.wantNoWarnings && strings.TrimSpace(result.warnings) != "" {
				t.Fatalf("warnings.txt not empty:\n%s", result.warnings)
			}
			for _, want := range tc.wantWarnings {
				if !strings.Contains(normalizeText(result.warnings), normalizeText(want)) {
					t.Fatalf("warnings.txt missing %q\nwarnings:\n%s", want, result.warnings)
				}
			}
			for _, forbidden := range tc.noWarningSubstrs {
				if strings.Contains(normalizeText(result.warnings), normalizeText(forbidden)) {
					t.Fatalf("warnings.txt unexpectedly contains %q\nwarnings:\n%s", forbidden, result.warnings)
				}
			}
		})
	}
}

func buildBinary(t *testing.T, goBinary, repoRoot string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "was-i-axios-pwned")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	cmd := exec.Command(goBinary, "build", "-o", binary, ".")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return binary
}

func runFixtureE2E(t *testing.T, repoRoot, binary, goModCache, goPath, fixture string) e2eResult {
	t.Helper()

	sandbox := t.TempDir()
	homeDir := filepath.Join(sandbox, "home")
	tmpDir := filepath.Join(sandbox, "tmp")
	goCacheDir := filepath.Join(sandbox, "gocache")
	binDir := filepath.Join(sandbox, "bin")
	workDir := filepath.Join(sandbox, "work")
	reportDir := filepath.Join(sandbox, "report")
	npmCacheDir := filepath.Join(sandbox, "npm-cache")
	npmLogsDir := filepath.Join(npmCacheDir, "_logs")
	npmRootDir := filepath.Join(sandbox, "global-node-modules")
	localAppDataDir := filepath.Join(sandbox, "LocalAppData")
	programDataDir := filepath.Join(sandbox, "ProgramData")

	for _, dir := range []string{
		homeDir,
		tmpDir,
		goCacheDir,
		binDir,
		workDir,
		reportDir,
		npmCacheDir,
		npmLogsDir,
		npmRootDir,
		localAppDataDir,
		programDataDir,
		filepath.Join(localAppDataDir, "npm-cache"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	fixtureRoot := filepath.Join(repoRoot, "testdata", "e2e", fixture, "input")
	if err := copyTree(fixtureRoot, workDir); err != nil {
		t.Fatalf("copy fixture %s: %v", fixture, err)
	}
	if err := writeCollectorStubs(binDir); err != nil {
		t.Fatalf("write stubs: %v", err)
	}

	env := envMap(os.Environ())
	env["HOME"] = homeDir
	env["TMPDIR"] = tmpDir
	env["TMP"] = tmpDir
	env["TEMP"] = tmpDir
	env["GOCACHE"] = goCacheDir
	env["AXIOS_E2E_NPM_CACHE"] = npmCacheDir
	env["AXIOS_E2E_NPM_ROOT"] = npmRootDir
	env["PATH"] = binDir + string(os.PathListSeparator) + env["PATH"]
	env["USERPROFILE"] = homeDir
	env["ProgramData"] = programDataDir
	env["LocalAppData"] = localAppDataDir
	if runtime.GOOS == "windows" {
		volume := filepath.VolumeName(homeDir)
		if volume == "" {
			volume = "C:"
		}
		env["SystemDrive"] = volume
		env["HOMEDRIVE"] = volume
		env["HOMEPATH"] = strings.TrimPrefix(homeDir, volume)
	}
	if goModCache != "" {
		env["GOMODCACHE"] = goModCache
	}
	if goPath != "" {
		env["GOPATH"] = goPath
	}

	cmd := exec.Command(binary, "--roots", workDir, "--report-dir", reportDir)
	cmd.Env = envList(env)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !strings.Contains(err.Error(), "exit status") || !errorAsExit(err, &exitErr) {
			t.Fatalf("go run failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
		}
		exitCode = exitErr.ExitCode()
	}

	summary := mustReadFile(t, filepath.Join(reportDir, "summary.txt"))
	findings := mustReadFile(t, filepath.Join(reportDir, "findings.tsv"))
	warnings := mustReadFile(t, filepath.Join(reportDir, "warnings.txt"))
	rawDirPath := filepath.Join(reportDir, "raw")
	info, err := os.Stat(rawDirPath)
	if err != nil {
		t.Fatalf("stat raw dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("raw path is not a directory: %s", rawDirPath)
	}

	return e2eResult{
		exitCode:   exitCode,
		stdout:     stdout.String(),
		stderr:     stderr.String(),
		summary:    summary,
		findings:   findings,
		warnings:   warnings,
		reportDir:  reportDir,
		rawDirPath: rawDirPath,
	}
}

func goEnv(goBinary, repoRoot, key string) (string, error) {
	cmd := exec.Command(goBinary, "env", key)
	cmd.Dir = repoRoot
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func copyTree(srcRoot, dstRoot string) error {
	return filepath.Walk(srcRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		dstPath := filepath.Join(dstRoot, rel)
		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode().Perm())
		}
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()

		out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, in)
		return err
	})
}

func writeCollectorStubs(binDir string) error {
	if runtime.GOOS == "windows" {
		return writeWindowsCollectorStubs(binDir)
	}
	return writeUnixCollectorStubs(binDir)
}

func writeUnixCollectorStubs(binDir string) error {
	scripts := map[string]string{
		"npm": `#!/bin/sh
if [ "$1" = "config" ] && [ "$2" = "get" ] && [ "$3" = "cache" ]; then
  printf '%s\n' "$AXIOS_E2E_NPM_CACHE"
  exit 0
fi
if [ "$1" = "root" ] && [ "$2" = "-g" ]; then
  printf '%s\n' "$AXIOS_E2E_NPM_ROOT"
  exit 0
fi
exit 0
`,
		"ps":         "#!/bin/sh\nexit 0\n",
		"lsof":       "#!/bin/sh\nexit 0\n",
		"netstat":    "#!/bin/sh\nexit 0\n",
		"journalctl": "#!/bin/sh\nexit 0\n",
		"log":        "#!/bin/sh\nexit 0\n",
	}

	for name, script := range scripts {
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			return err
		}
	}
	return nil
}

func writeWindowsCollectorStubs(binDir string) error {
	scripts := map[string]string{
		"npm.bat": `@echo off
if "%1 %2 %3"=="config get cache" (
  echo %AXIOS_E2E_NPM_CACHE%
  exit /b 0
)
if "%1 %2"=="root -g" (
  echo %AXIOS_E2E_NPM_ROOT%
  exit /b 0
)
exit /b 0
`,
		"powershell.bat": "@echo off\r\nexit /b 0\r\n",
		"netstat.bat":    "@echo off\r\nexit /b 0\r\n",
	}

	for name, script := range scripts {
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(bytes)
}

func normalizeText(text string) string {
	return strings.ReplaceAll(text, `\`, `/`)
}

func envMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, pair := range env {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		out[key] = value
	}
	return out
}

func envList(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, fmt.Sprintf("%s=%s", key, env[key]))
	}
	return out
}

func errorAsExit(err error, target **exec.ExitError) bool {
	return errors.As(err, target)
}
