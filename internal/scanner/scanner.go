package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
)

const (
	campaignID        = "6202033"
	c2Domain          = "sfrclak.com"
	c2IP              = "142.11.206.73"
	c2URL             = "http://sfrclak.com:8000/" + campaignID
	setupSHA256       = "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09"
	axios1141SHA1     = "2553649f2322049666871cea80a5d0d6adc700ca"
	axios0304SHA1     = "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71"
	plainCryptoSHA1   = "07d889e2dadce6f3910dcbc253317d28ca61c766"
	maxSnippetLines   = 20
	maxTreeMatchLines = 50
)

var (
	lockfileNames = map[string]struct{}{
		"package-lock.json":   {},
		"npm-shrinkwrap.json": {},
		"yarn.lock":           {},
		"pnpm-lock.yaml":      {},
		".package-lock.json":  {},
	}
	excludedDirNames = map[string]struct{}{
		".git":         {},
		".cache":       {},
		"testdata":     {},
		"dist":         {},
		"build":        {},
		"target":       {},
		".pnpm-store":  {},
		".yarn":        {},
		".npm":         {},
		".Trash":       {},
		"Library":      {},
		"Movies":       {},
		"Music":        {},
		"Pictures":     {},
		"Applications": {},
	}
	namedTarballs = map[string]string{
		"axios-1.14.1.tgz":          axios1141SHA1,
		"axios-0.30.4.tgz":          axios0304SHA1,
		"plain-crypto-js-4.2.1.tgz": plainCryptoSHA1,
	}
	textIndicators = []string{
		"plain-crypto-js",
		"axios@1.14.1",
		"axios@0.30.4",
		"axios-1.14.1",
		"axios-0.30.4",
		c2Domain,
		c2IP,
		campaignID,
		"packages.npm.org/product0",
		"packages.npm.org/product1",
		"packages.npm.org/product2",
	}
	c2ConnectionIndicators = []string{
		c2IP + ":8000",
		c2IP + ".8000",
		c2Domain + ":8000",
		c2Domain + ".8000",
	}
	processIndicators = []string{
		"com.apple.act.mond",
		"/tmp/ld.py",
		campaignID,
		c2Domain,
		"plain-crypto-js",
		"packages.npm.org/product0",
		"packages.npm.org/product1",
		"packages.npm.org/product2",
		"wt.exe",
		"osascript",
		"cscript",
	}
	vulnerableAxiosVersions = []string{"1.14.1", "0.30.4"}
)

type Scanner struct {
	cfg    Config
	runner Runner
}

type systemRunner struct{}

type scanState struct {
	report            Report
	findingSet        map[string]struct{}
	warningSet        map[string]struct{}
	rangeRiskSet      map[string]struct{}
	rawSet            map[string]struct{}
	projectEvidence   map[string]struct{}
	pendingRangeRisks []RangeRisk
	npmLogDirs        []string
	npmCacheDirs      []string
}

type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type npmLockFile struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmLockPackage `json:"packages"`
	Dependencies    map[string]npmLockDep     `json:"dependencies"`
}

type npmLockPackage struct {
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	Resolved         string            `json:"resolved"`
	Integrity        string            `json:"integrity"`
	HasInstallScript bool              `json:"hasInstallScript"`
	Dependencies     map[string]string `json:"dependencies"`
}

type npmLockDep struct {
	Version          string                `json:"version"`
	Resolved         string                `json:"resolved"`
	Integrity        string                `json:"integrity"`
	HasInstallScript bool                  `json:"hasInstallScript"`
	Dependencies     map[string]npmLockDep `json:"dependencies"`
}

func (systemRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (systemRunner) CombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func New(cfg Config, opts ...Option) *Scanner {
	collected := collectOptions(opts...)
	if collected.runner == nil {
		collected.runner = systemRunner{}
	}
	cfg = normalizeConfig(cfg)
	return &Scanner{
		cfg:    cfg,
		runner: collected.runner,
	}
}

func normalizeConfig(cfg Config) Config {
	if cfg.Since == "" {
		cfg.Since = DefaultSince
	}
	if cfg.Env == nil {
		cfg.Env = map[string]string{}
	}
	return cfg
}

func (s *Scanner) Run(ctx context.Context) (*Report, error) {
	state := &scanState{
		report: Report{
			Verdict:  NoEvidence,
			Coverage: CoverageComplete,
			Platform: s.cfg.Platform,
			Since:    s.cfg.Since,
			Deep:     s.cfg.Deep,
			Raw:      map[string][]RawSnippet{},
		},
		findingSet:      map[string]struct{}{},
		warningSet:      map[string]struct{}{},
		rangeRiskSet:    map[string]struct{}{},
		rawSet:          map[string]struct{}{},
		projectEvidence: map[string]struct{}{},
	}

	if err := s.prepareTargets(ctx, state); err != nil {
		return nil, err
	}
	for _, root := range state.report.Roots {
		s.scanProjectRoot(root, state)
	}
	for _, dir := range state.npmLogDirs {
		s.scanNPMLogsDir(dir, state)
	}
	for _, dir := range state.npmCacheDirs {
		s.scanNPMCacheDir(dir, state)
	}

	s.scanProcesses(ctx, state)
	s.scanNetwork(ctx, state)

	switch s.cfg.Platform {
	case "darwin":
		s.scanMacOS(ctx, state)
	case "windows":
		s.scanWindows(state)
	default:
		s.scanUnixLike(ctx, state)
	}

	s.finalizeRangeRisks(state)
	return &state.report, nil
}

func (s *Scanner) prepareTargets(ctx context.Context, state *scanState) error {
	rootSet := map[string]struct{}{}
	addRoot := func(path string) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return
		}
		if _, exists := rootSet[path]; exists {
			return
		}
		rootSet[path] = struct{}{}
		state.report.Roots = append(state.report.Roots, path)
	}
	addLogDir := func(path string) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return
		}
		for _, existing := range state.npmLogDirs {
			if existing == path {
				return
			}
		}
		state.npmLogDirs = append(state.npmLogDirs, path)
	}
	addCacheDir := func(path string) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return
		}
		for _, existing := range state.npmCacheDirs {
			if existing == path {
				return
			}
		}
		state.npmCacheDirs = append(state.npmCacheDirs, path)
	}

	addRoot(s.cfg.WorkingDir)
	addRoot(s.cfg.HomeDir)
	for _, root := range s.cfg.Roots {
		addRoot(root)
	}

	switch s.cfg.Platform {
	case "darwin":
		if s.cfg.Deep {
			addRoot("/")
		}
	case "windows":
		if s.cfg.Deep {
			for _, root := range windowsFilesystemRoots(s.cfg) {
				addRoot(root)
			}
		}
	default:
		if s.cfg.Deep {
			addRoot("/")
		}
	}

	for _, cacheDir := range s.defaultCacheDirs() {
		addCacheDir(cacheDir)
		addLogDir(filepath.Join(cacheDir, "_logs"))
	}
	if npmCache := s.npmCommandOutput(ctx, "config", "get", "cache"); npmCache != "" {
		addCacheDir(npmCache)
		addLogDir(filepath.Join(npmCache, "_logs"))
	}
	if npmRoot := s.npmCommandOutput(ctx, "root", "-g"); npmRoot != "" {
		addRoot(npmRoot)
	}

	if len(state.report.Roots) == 0 {
		return fmt.Errorf("no readable scan roots were found")
	}
	state.report.Roots = pruneNestedRoots(state.report.Roots)
	sort.Strings(state.npmLogDirs)
	sort.Strings(state.npmCacheDirs)
	return nil
}

func globDirs(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	var dirs []string
	for _, match := range matches {
		info, err := os.Stat(match)
		if err == nil && info.IsDir() {
			dirs = append(dirs, match)
		}
	}
	return dirs
}

func windowsFilesystemRoots(cfg Config) []string {
	seen := map[string]struct{}{}
	var roots []string
	add := func(path string) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		volume := filepath.VolumeName(path)
		if volume == "" {
			return
		}
		root := volume + string(os.PathSeparator)
		if _, exists := seen[root]; exists {
			return
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
	}

	add(firstNonEmpty(cfg.WorkingDir, cfg.HomeDir))
	for _, root := range cfg.Roots {
		add(root)
	}
	add(firstNonEmpty(cfg.Env["SystemDrive"], "C:"))
	return roots
}

func pruneNestedRoots(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	normalized := append([]string(nil), paths...)
	sort.Strings(normalized)

	var pruned []string
	for _, path := range normalized {
		nested := false
		for _, existing := range pruned {
			if path == existing || isSubpath(path, existing) {
				nested = true
				break
			}
		}
		if !nested {
			pruned = append(pruned, path)
		}
	}
	return pruned
}

func isSubpath(path, root string) bool {
	if path == root {
		return false
	}
	if root == string(os.PathSeparator) {
		return strings.HasPrefix(path, root)
	}
	if vol := filepath.VolumeName(root); vol != "" && path == vol+string(os.PathSeparator) {
		return false
	}
	return strings.HasPrefix(path, root+string(os.PathSeparator))
}

func (s *Scanner) defaultCacheDirs() []string {
	var dirs []string
	if home := s.cfg.HomeDir; home != "" {
		dirs = append(dirs, filepath.Join(home, ".npm"))
		if s.cfg.Platform == "windows" {
			if localAppData := s.env("LocalAppData"); localAppData != "" {
				dirs = append(dirs, filepath.Join(localAppData, "npm-cache"))
			}
		}
	}
	return dirs
}

func (s *Scanner) npmCommandOutput(ctx context.Context, args ...string) string {
	if _, err := s.runner.LookPath("npm"); err != nil {
		return ""
	}
	out, err := s.runner.CombinedOutput(ctx, "npm", args...)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (s *Scanner) scanProjectRoot(root string, state *scanState) {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		s.addWarning(state, WarningCoverage, fmt.Sprintf("Could not read root %s.", root))
		return
	}

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if path == root {
				s.addWarning(state, WarningCoverage, fmt.Sprintf("Could not read root %s.", root))
			}
			return nil
		}
		base := d.Name()
		if d.IsDir() {
			if base == "node_modules" {
				s.scanNodeModulesTree(path, state)
				return filepath.SkipDir
			}
			if path != root {
				if _, excluded := excludedDirNames[base]; excluded {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if _, ok := namedTarballs[base]; ok {
			s.scanNamedTarball(path, state)
			return nil
		}

		switch base {
		case "package.json":
			s.scanPackageJSON(path, filepath.Dir(path), state)
		case "package-lock.json", "npm-shrinkwrap.json":
			s.scanNPMLockfile(path, filepath.Dir(path), state)
		case "yarn.lock":
			s.scanYarnLock(path, filepath.Dir(path), state)
		case "pnpm-lock.yaml":
			s.scanPNPMLock(path, filepath.Dir(path), state)
		}
		return nil
	})
}

func (s *Scanner) scanNodeModulesTree(nodeModulesPath string, state *scanState) {
	projectDir := filepath.Dir(nodeModulesPath)
	if lockfile := filepath.Join(nodeModulesPath, ".package-lock.json"); isFile(lockfile) {
		s.scanNPMLockfile(lockfile, projectDir, state)
	}
	if plainCryptoDir := filepath.Join(nodeModulesPath, "plain-crypto-js"); isDir(plainCryptoDir) {
		s.scanPlainCryptoDir(plainCryptoDir, projectDir, state)
	}

	entries, err := os.ReadDir(nodeModulesPath)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		child := filepath.Join(nodeModulesPath, entry.Name())
		if strings.HasPrefix(entry.Name(), "@") {
			scopedEntries, err := os.ReadDir(child)
			if err != nil {
				continue
			}
			for _, scoped := range scopedEntries {
				if !scoped.IsDir() {
					continue
				}
				nested := filepath.Join(child, scoped.Name(), "node_modules")
				if isDir(nested) {
					s.scanNodeModulesTree(nested, state)
				}
			}
			continue
		}
		nested := filepath.Join(child, "node_modules")
		if isDir(nested) {
			s.scanNodeModulesTree(nested, state)
		}
	}
}

func (s *Scanner) scanPlainCryptoDir(dir, projectDir string, state *scanState) {
	s.addFinding(state, projectDir, Finding{
		Severity:  Confirmed,
		Source:    "package_directory",
		Indicator: "plain-crypto-js",
		Location:  dir,
		Detail:    "Found plain-crypto-js under node_modules. This dependency only appeared in the malicious axios releases.",
	})

	packageJSONPath := filepath.Join(dir, "package.json")
	if isFile(packageJSONPath) {
		if bytes, err := os.ReadFile(packageJSONPath); err == nil {
			if strings.Contains(string(bytes), `"version": "4.2.0"`) || strings.Contains(compactJSON(bytes), `"version":"4.2.0"`) {
				s.addFinding(state, projectDir, Finding{
					Severity:  Confirmed,
					Source:    "manifest_swap",
					Indicator: "plain-crypto-js fake 4.2.0 manifest",
					Location:  packageJSONPath,
					Detail:    "package.json reports version 4.2.0, which matches the documented anti-forensics swap after postinstall.",
				})
			}
			if strings.Contains(string(bytes), `"postinstall": "node setup.js"`) || strings.Contains(compactJSON(bytes), `"postinstall":"node setup.js"`) {
				s.addFinding(state, projectDir, Finding{
					Severity:  Confirmed,
					Source:    "manifest_hook",
					Indicator: "postinstall node setup.js",
					Location:  packageJSONPath,
					Detail:    "package.json still contains the malicious postinstall hook.",
				})
			}
			s.addRaw(state, "plain-crypto", packageJSONPath, matchingLines(string(bytes), []string{"plain-crypto-js", `"version"`, "postinstall", "setup.js"}, maxSnippetLines))
		}
	}

	setupPath := filepath.Join(dir, "setup.js")
	if isFile(setupPath) {
		digest, _ := fileSHA256(setupPath)
		detail := fmt.Sprintf("Residual setup.js found inside plain-crypto-js. SHA-256=%s.", digest)
		indicator := "setup.js residue"
		if digest == setupSHA256 {
			detail = "Residual setup.js matches the published malicious SHA-256."
			indicator = "setup.js SHA-256 match"
		}
		s.addFinding(state, projectDir, Finding{
			Severity:  Confirmed,
			Source:    "setup_js",
			Indicator: indicator,
			Location:  setupPath,
			Detail:    detail,
		})
		if snippet := readFirstLines(setupPath, maxSnippetLines); snippet != "" {
			s.addRaw(state, "plain-crypto-setup", setupPath, snippet)
		}
	}

	packageMDPath := filepath.Join(dir, "package.md")
	if isFile(packageMDPath) {
		s.addFinding(state, projectDir, Finding{
			Severity:  Confirmed,
			Source:    "anti_forensics",
			Indicator: "package.md",
			Location:  packageMDPath,
			Detail:    "Found package.md, the decoy manifest used to replace the malicious package.json.",
		})
		if bytes, err := os.ReadFile(packageMDPath); err == nil {
			s.addRaw(state, "plain-crypto", packageMDPath, matchingLines(string(bytes), []string{"plain-crypto-js", "4.2.0"}, maxSnippetLines))
		}
	}
}

func (s *Scanner) scanPackageJSON(path, projectDir string, state *scanState) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var manifest packageJSON
	if err := json.Unmarshal(bytes, &manifest); err != nil {
		return
	}

	maps := []map[string]string{
		manifest.Dependencies,
		manifest.DevDependencies,
		manifest.OptionalDependencies,
		manifest.PeerDependencies,
	}
	foundExact := false
	for _, deps := range maps {
		for name, spec := range deps {
			switch name {
			case "plain-crypto-js":
				s.addFinding(state, projectDir, Finding{
					Severity:  LikelyExposed,
					Source:    "manifest",
					Indicator: "plain-crypto-js reference",
					Location:  path,
					Detail:    "Manifest references the injected dependency plain-crypto-js.",
				})
				foundExact = true
			case "axios":
				if version, ok := exactVulnerableVersion(spec); ok {
					s.addFinding(state, projectDir, Finding{
						Severity:  LikelyExposed,
						Source:    "manifest",
						Indicator: "axios@" + version + " reference",
						Location:  path,
						Detail:    fmt.Sprintf("Manifest references the compromised axios version %s.", version),
					})
					foundExact = true
					continue
				}
				if versions := semverRiskVersions(spec); len(versions) > 0 {
					s.addRangeRisk(state, RangeRisk{
						Manifest: path,
						Project:  projectDir,
						Spec:     spec,
						Versions: versions,
					})
				}
			}
		}
	}

	if foundExact {
		s.addRaw(state, "manifests", path, matchingLines(string(bytes), []string{"axios", "plain-crypto-js", "1.14.1", "0.30.4"}, maxSnippetLines))
	}
}

func (s *Scanner) scanNPMLockfile(path, projectDir string, state *scanState) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var lock npmLockFile
	if err := json.Unmarshal(bytes, &lock); err != nil {
		return
	}

	for packagePath, pkg := range lock.Packages {
		name := packageNameFromPath(packagePath, pkg.Name)
		switch name {
		case "plain-crypto-js":
			s.addFinding(state, projectDir, Finding{
				Severity:  LikelyExposed,
				Source:    "lockfile",
				Indicator: "plain-crypto-js reference",
				Location:  path,
				Detail:    formatLockDetail("Lockfile references the injected dependency plain-crypto-js.", pkg.Resolved, pkg.Integrity, pkg.HasInstallScript),
			})
		case "axios":
			if isVulnerableAxiosVersion(pkg.Version) {
				s.addFinding(state, projectDir, Finding{
					Severity:  LikelyExposed,
					Source:    "lockfile",
					Indicator: "axios@" + pkg.Version + " reference",
					Location:  path,
					Detail:    formatLockDetail("Lockfile references a compromised axios version.", pkg.Resolved, pkg.Integrity, pkg.HasInstallScript),
				})
			}
		}
	}
	for name, dep := range lock.Dependencies {
		s.walkNPMDependency(path, projectDir, name, dep, state)
	}

	s.addRaw(state, "manifests", path, matchingLines(string(bytes), []string{"axios", "plain-crypto-js", "1.14.1", "0.30.4", "hasInstallScript", "resolved", "integrity"}, maxSnippetLines))
}

func (s *Scanner) walkNPMDependency(path, projectDir, name string, dep npmLockDep, state *scanState) {
	switch name {
	case "plain-crypto-js":
		s.addFinding(state, projectDir, Finding{
			Severity:  LikelyExposed,
			Source:    "lockfile",
			Indicator: "plain-crypto-js reference",
			Location:  path,
			Detail:    formatLockDetail("Lockfile references the injected dependency plain-crypto-js.", dep.Resolved, dep.Integrity, dep.HasInstallScript),
		})
	case "axios":
		if isVulnerableAxiosVersion(dep.Version) {
			s.addFinding(state, projectDir, Finding{
				Severity:  LikelyExposed,
				Source:    "lockfile",
				Indicator: "axios@" + dep.Version + " reference",
				Location:  path,
				Detail:    formatLockDetail("Lockfile references a compromised axios version.", dep.Resolved, dep.Integrity, dep.HasInstallScript),
			})
		}
	}
	for childName, child := range dep.Dependencies {
		s.walkNPMDependency(path, projectDir, childName, child, state)
	}
}

func (s *Scanner) scanYarnLock(path, projectDir string, state *scanState) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return
	}
	blocks := parseYarnBlocks(string(bytes))
	for _, block := range blocks {
		if strings.Contains(block.Keys, "plain-crypto-js@") {
			s.addFinding(state, projectDir, Finding{
				Severity:  LikelyExposed,
				Source:    "lockfile",
				Indicator: "plain-crypto-js reference",
				Location:  path,
				Detail:    formatLockDetail("Yarn lockfile references the injected dependency plain-crypto-js.", block.Resolved, block.Integrity, false),
			})
		}
		if strings.Contains(block.Keys, "axios@") && isVulnerableAxiosVersion(block.Version) {
			s.addFinding(state, projectDir, Finding{
				Severity:  LikelyExposed,
				Source:    "lockfile",
				Indicator: "axios@" + block.Version + " reference",
				Location:  path,
				Detail:    formatLockDetail("Yarn lockfile references a compromised axios version.", block.Resolved, block.Integrity, false),
			})
		}
	}
	s.addRaw(state, "manifests", path, matchingLines(string(bytes), []string{"axios@", "plain-crypto-js@", "1.14.1", "0.30.4"}, maxSnippetLines))
}

func (s *Scanner) scanPNPMLock(path, projectDir string, state *scanState) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(bytes)
	pnpmPackageRE := regexp.MustCompile(`(?m)^[ \t]*['"]?/?(axios|plain-crypto-js)@([^:'"\s]+)[^:]*['"]?:\s*$`)
	for _, match := range pnpmPackageRE.FindAllStringSubmatch(content, -1) {
		name := match[1]
		version := match[2]
		switch name {
		case "plain-crypto-js":
			s.addFinding(state, projectDir, Finding{
				Severity:  LikelyExposed,
				Source:    "lockfile",
				Indicator: "plain-crypto-js reference",
				Location:  path,
				Detail:    "pnpm lockfile references the injected dependency plain-crypto-js.",
			})
		case "axios":
			if isVulnerableAxiosVersion(version) {
				s.addFinding(state, projectDir, Finding{
					Severity:  LikelyExposed,
					Source:    "lockfile",
					Indicator: "axios@" + version + " reference",
					Location:  path,
					Detail:    "pnpm lockfile references a compromised axios version.",
				})
			}
		}
	}
	s.addRaw(state, "manifests", path, matchingLines(content, []string{"axios@", "plain-crypto-js@", "1.14.1", "0.30.4"}, maxSnippetLines))
}

func (s *Scanner) scanNamedTarball(path string, state *scanState) {
	expected, ok := namedTarballs[filepath.Base(path)]
	if !ok {
		return
	}
	digest, err := fileSHA1(path)
	if err != nil {
		return
	}
	if digest != expected {
		return
	}
	s.addFinding(state, "", Finding{
		Severity:  LikelyExposed,
		Source:    "tarball",
		Indicator: filepath.Base(path),
		Location:  path,
		Detail:    "Found a tarball whose SHA-1 matches the published malicious package.",
	})
	s.addRaw(state, "tarballs", path, "sha1="+digest)
}

func (s *Scanner) scanNPMLogsDir(dir string, state *scanState) {
	if !isDir(dir) {
		return
	}
	if matches := searchTreeForIndicators(dir, textIndicators, maxTreeMatchLines); matches != "" {
		s.addFinding(state, "", Finding{
			Severity:  LikelyExposed,
			Source:    "npm_logs",
			Indicator: "npm log IOC",
			Location:  dir,
			Detail:    "npm logs contain one or more compromise indicators.",
		})
		s.addRaw(state, "npm-logs", dir, matches)
	}
}

func (s *Scanner) scanNPMCacheDir(dir string, state *scanState) {
	if !isDir(dir) {
		return
	}
	metadataDir := filepath.Join(dir, "_cacache", "index-v5")
	if isDir(metadataDir) {
		patterns := []string{
			"axios/-/axios-1.14.1.tgz",
			"axios/-/axios-0.30.4.tgz",
			"plain-crypto-js/-/plain-crypto-js-4.2.1.tgz",
		}
		if matches := searchTreeForIndicators(metadataDir, patterns, maxTreeMatchLines); matches != "" {
			s.addFinding(state, "", Finding{
				Severity:  LikelyExposed,
				Source:    "npm_cache",
				Indicator: "cache metadata IOC",
				Location:  metadataDir,
				Detail:    "npm cache metadata references a malicious tarball URL.",
			})
			s.addRaw(state, "npm-cache", metadataDir, matches)
		}
	}

	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if _, ok := namedTarballs[filepath.Base(path)]; ok {
			s.scanNamedTarball(path, state)
		}
		return nil
	})
}

func (s *Scanner) scanProcesses(ctx context.Context, state *scanState) {
	var output string
	switch s.cfg.Platform {
	case "windows":
		if _, err := s.runner.LookPath("powershell"); err == nil {
			out, err := s.runner.CombinedOutput(ctx, "powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_Process | Select-Object ProcessId,CommandLine | Format-Table -HideTableHeaders")
			if err == nil {
				output = string(out)
			}
		}
	default:
		if _, err := s.runner.LookPath("ps"); err == nil {
			out, err := s.runner.CombinedOutput(ctx, "ps", "ax", "-o", "pid=,command=")
			if err == nil {
				output = string(out)
			}
		}
	}
	if output == "" {
		return
	}
	if matches := matchingLines(output, processIndicators, maxTreeMatchLines); matches != "" {
		s.addFinding(state, "", Finding{
			Severity:  Confirmed,
			Source:    "processes",
			Indicator: "running IOC process",
			Location:  "process table",
			Detail:    "Active processes contain command-line indicators from the malicious installer or stage-two payload.",
		})
		s.addRaw(state, "processes", "process table", matches)
	}
}

func (s *Scanner) scanNetwork(ctx context.Context, state *scanState) {
	var output string
	if s.cfg.Platform == "windows" {
		if _, err := s.runner.LookPath("netstat"); err == nil {
			out, err := s.runner.CombinedOutput(ctx, "netstat", "-ano")
			if err == nil {
				output = string(out)
			}
		}
	} else {
		if _, err := s.runner.LookPath("lsof"); err == nil {
			out, err := s.runner.CombinedOutput(ctx, "lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED")
			if err == nil {
				output = string(out)
			}
		}
		if output == "" {
			if _, err := s.runner.LookPath("netstat"); err == nil {
				out, err := s.runner.CombinedOutput(ctx, "netstat", "-an")
				if err == nil {
					output = string(out)
				}
			}
		}
	}
	if output == "" {
		return
	}
	if matches := matchingLines(output, c2ConnectionIndicators, maxTreeMatchLines); matches != "" {
		s.addFinding(state, "", Finding{
			Severity:  Confirmed,
			Source:    "network",
			Indicator: "C2 connection",
			Location:  "active connections",
			Detail:    "Active network telemetry shows a connection to the published C2 endpoint.",
		})
		s.addRaw(state, "network", "active connections", matches)
	}
}

func (s *Scanner) scanMacOS(ctx context.Context, state *scanState) {
	for _, path := range []string{
		"/Library/Caches/com.apple.act.mond",
		filepath.Join(firstNonEmpty(s.env("TMPDIR"), os.TempDir()), campaignID),
	} {
		if isFile(path) {
			s.addFinding(state, "", Finding{
				Severity:  Confirmed,
				Source:    "artifact",
				Indicator: path,
				Location:  path,
				Detail:    "Found the documented macOS second-stage artifact path.",
			})
		}
	}

	if _, err := s.runner.LookPath("log"); err != nil {
		s.addWarning(state, WarningCoverage, "macOS unified log collector unavailable because the log command is missing.")
		return
	}
	out, err := s.runner.CombinedOutput(ctx, "log", "show", "--style", "compact", "--start", s.cfg.Since, "--predicate", `eventMessage CONTAINS[c] "sfrclak.com" OR eventMessage CONTAINS[c] "6202033" OR eventMessage CONTAINS[c] "packages.npm.org/product0" OR eventMessage CONTAINS[c] "com.apple.act.mond" OR process CONTAINS[c] "osascript"`)
	output := string(out)
	if err != nil && permissionDenied(output) {
		s.addWarning(state, WarningCoverage, "macOS unified log access was denied. Re-run with elevated privileges for fuller coverage.")
	}
	if matches := matchingLines(output, []string{c2Domain, campaignID, "packages.npm.org/product0", "com.apple.act.mond", "osascript"}, maxTreeMatchLines); matches != "" {
		s.addFinding(state, "", Finding{
			Severity:  LikelyExposed,
			Source:    "os_logs",
			Indicator: "macOS unified log IOC",
			Location:  "unified log",
			Detail:    "macOS unified logs contain one or more compromise indicators.",
		})
		s.addRaw(state, "macos-logs", "unified log", matches)
	}
}

func (s *Scanner) scanUnixLike(ctx context.Context, state *scanState) {
	linuxArtifact := filepath.Join(firstNonEmpty(s.env("TMPDIR"), os.TempDir()), "ld.py")
	if isFile(linuxArtifact) {
		s.addFinding(state, "", Finding{
			Severity:  Confirmed,
			Source:    "artifact",
			Indicator: linuxArtifact,
			Location:  linuxArtifact,
			Detail:    "Found the documented Linux stage-two dropper path.",
		})
	}

	if _, err := s.runner.LookPath("journalctl"); err == nil {
		out, err := s.runner.CombinedOutput(ctx, "journalctl", "--since", s.cfg.Since, "--no-pager")
		output := string(out)
		if err != nil && permissionDenied(output) {
			s.addWarning(state, WarningCoverage, "journalctl access was denied or incomplete. Re-run with elevated privileges for fuller Linux log coverage.")
		}
		if matches := matchingLines(output, append([]string{}, textIndicators...), maxTreeMatchLines); matches != "" {
			s.addFinding(state, "", Finding{
				Severity:  LikelyExposed,
				Source:    "os_logs",
				Indicator: "journalctl IOC",
				Location:  "journalctl",
				Detail:    "journalctl contains one or more compromise indicators.",
			})
			s.addRaw(state, "linux-logs", "journalctl", matches)
		}
	}

	if s.cfg.Deep || !isDir("/run/systemd/journal") {
		for _, file := range []string{"/var/log/syslog", "/var/log/messages", "/var/log/auth.log", "/var/log/secure"} {
			if !isFile(file) {
				continue
			}
			bytes, err := os.ReadFile(file)
			if err != nil {
				s.addWarning(state, WarningCoverage, fmt.Sprintf("Could not read %s. Re-run with elevated privileges for fuller Linux log coverage.", file))
				continue
			}
			if matches := matchingLines(string(bytes), textIndicators, maxTreeMatchLines); matches != "" {
				s.addFinding(state, "", Finding{
					Severity:  LikelyExposed,
					Source:    "os_logs",
					Indicator: "Linux log IOC",
					Location:  file,
					Detail:    "Linux logs contain one or more compromise indicators.",
				})
				s.addRaw(state, "linux-logs", file, matches)
			}
		}
	}
}

func (s *Scanner) scanWindows(state *scanState) {
	programData := firstNonEmpty(s.env("ProgramData"), filepath.Join(firstNonEmpty(s.env("SystemDrive"), "C:"), "ProgramData"))
	tempDir := firstNonEmpty(s.env("TEMP"), s.env("TMP"), os.TempDir())
	for _, path := range []string{
		filepath.Join(programData, "wt.exe"),
		filepath.Join(tempDir, campaignID+".ps1"),
		filepath.Join(tempDir, campaignID+".vbs"),
	} {
		if isFile(path) {
			s.addFinding(state, "", Finding{
				Severity:  Confirmed,
				Source:    "artifact",
				Indicator: path,
				Location:  path,
				Detail:    "Found the documented Windows payload artifact.",
			})
		}
	}
}

func (s *Scanner) finalizeRangeRisks(state *scanState) {
	for _, risk := range state.pendingRangeRisks {
		if _, exists := state.projectEvidence[risk.Project]; exists {
			continue
		}
		key := risk.Manifest + "\x00" + risk.Spec + "\x00" + strings.Join(risk.Versions, ",")
		if _, exists := state.rangeRiskSet[key]; exists {
			continue
		}
		state.rangeRiskSet[key] = struct{}{}
		state.report.RangeRisks = append(state.report.RangeRisks, risk)
		message := fmt.Sprintf("%s allows axios %s, which could have resolved to compromised version(s): %s", risk.Manifest, risk.Spec, strings.Join(risk.Versions, ", "))
		s.addWarning(state, WarningRangeRisk, message)
	}
	sort.Slice(state.report.RangeRisks, func(i, j int) bool {
		if state.report.RangeRisks[i].Manifest == state.report.RangeRisks[j].Manifest {
			return state.report.RangeRisks[i].Spec < state.report.RangeRisks[j].Spec
		}
		return state.report.RangeRisks[i].Manifest < state.report.RangeRisks[j].Manifest
	})
}

func BuildSummary(report *Report) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Axios npm compromise triage\n")
	fmt.Fprintf(&builder, "Verdict: %s\n", report.Verdict)
	fmt.Fprintf(&builder, "Coverage: %s\n", report.Coverage)
	fmt.Fprintf(&builder, "Platform: %s\n", report.Platform)
	fmt.Fprintf(&builder, "Since: %s\n", report.Since)
	fmt.Fprintf(&builder, "Deep Scan: %s\n", boolToYesNo(report.Deep))
	fmt.Fprintf(&builder, "Findings: %d\n", len(report.Findings))
	fmt.Fprintf(&builder, "Warnings: %d\n", len(report.Warnings))
	fmt.Fprintf(&builder, "C2: %s (%s)\n", c2Domain, c2IP)
	fmt.Fprintf(&builder, "Roots:\n")
	for _, root := range report.Roots {
		fmt.Fprintf(&builder, "  - %s\n", root)
	}

	if len(report.RangeRisks) > 0 {
		fmt.Fprintf(&builder, "\nPotential Range Risks\n")
		for _, risk := range report.RangeRisks {
			fmt.Fprintf(&builder, "  - %s | axios %s | admits %s\n", risk.Manifest, risk.Spec, strings.Join(risk.Versions, ", "))
		}
	}
	if len(report.Findings) > 0 {
		fmt.Fprintf(&builder, "\nFindings\n")
		for _, finding := range report.Findings {
			fmt.Fprintf(&builder, "  - [%s] %s | %s | %s | %s\n", finding.Severity, finding.Source, finding.Indicator, finding.Location, finding.Detail)
		}
	}
	if len(report.Warnings) > 0 {
		fmt.Fprintf(&builder, "\nWarnings\n")
		for _, warning := range report.Warnings {
			fmt.Fprintf(&builder, "  - [%s] %s\n", warning.Class, warning.Message)
		}
	}
	if report.Verdict != NoEvidence {
		fmt.Fprintf(&builder, "\nImmediate Next Steps\n")
		fmt.Fprintf(&builder, "  - Treat this host as compromised until proven otherwise.\n")
		fmt.Fprintf(&builder, "  - Isolate the machine, rotate secrets from a clean system, and rebuild from known-good media.\n")
		fmt.Fprintf(&builder, "  - Review installs and logs around 2026-03-31 00:21:00Z through 2026-03-31 03:15:30Z.\n")
	}
	return builder.String()
}

func WriteReportBundle(dir string, report *Report, summary string) error {
	if err := os.MkdirAll(filepath.Join(dir, "raw"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "summary.txt"), []byte(summary), 0o644); err != nil {
		return err
	}
	var findings bytes.Buffer
	for _, finding := range report.Findings {
		fmt.Fprintf(&findings, "%s\t%s\t%s\t%s\t%s\n", sanitizeField(string(finding.Severity)), sanitizeField(finding.Source), sanitizeField(finding.Indicator), sanitizeField(finding.Location), sanitizeField(finding.Detail))
	}
	if err := os.WriteFile(filepath.Join(dir, "findings.tsv"), findings.Bytes(), 0o644); err != nil {
		return err
	}
	var warnings bytes.Buffer
	for _, warning := range report.Warnings {
		fmt.Fprintf(&warnings, "%s\t%s\n", warning.Class, sanitizeField(warning.Message))
	}
	if err := os.WriteFile(filepath.Join(dir, "warnings.txt"), warnings.Bytes(), 0o644); err != nil {
		return err
	}
	for name, snippets := range report.Raw {
		var raw bytes.Buffer
		for _, snippet := range snippets {
			fmt.Fprintf(&raw, "### %s\n%s\n\n", sanitizeField(snippet.Title), snippet.Body)
		}
		if err := os.WriteFile(filepath.Join(dir, "raw", name+".txt"), raw.Bytes(), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scanner) addFinding(state *scanState, projectDir string, finding Finding) {
	finding.Source = sanitizeField(finding.Source)
	finding.Indicator = sanitizeField(finding.Indicator)
	finding.Location = sanitizeField(finding.Location)
	finding.Detail = sanitizeField(finding.Detail)
	key := string(finding.Severity) + "\x00" + finding.Source + "\x00" + finding.Indicator + "\x00" + finding.Location + "\x00" + finding.Detail
	if _, exists := state.findingSet[key]; exists {
		return
	}
	state.findingSet[key] = struct{}{}
	state.report.Findings = append(state.report.Findings, finding)
	switch finding.Severity {
	case Confirmed:
		state.report.Verdict = Confirmed
	case LikelyExposed:
		if state.report.Verdict == NoEvidence {
			state.report.Verdict = LikelyExposed
		}
	}
	if projectDir != "" {
		state.projectEvidence[filepath.Clean(projectDir)] = struct{}{}
	}
}

func (s *Scanner) addWarning(state *scanState, class WarningClass, message string) {
	message = sanitizeField(message)
	key := string(class) + "\x00" + message
	if _, exists := state.warningSet[key]; exists {
		return
	}
	state.warningSet[key] = struct{}{}
	state.report.Warnings = append(state.report.Warnings, Warning{Class: class, Message: message})
	if class == WarningCoverage {
		state.report.Coverage = CoveragePartial
	}
}

func (s *Scanner) addRangeRisk(state *scanState, risk RangeRisk) {
	risk.Manifest = filepath.Clean(risk.Manifest)
	risk.Project = filepath.Clean(risk.Project)
	state.pendingRangeRisks = append(state.pendingRangeRisks, risk)
}

func (s *Scanner) addRaw(state *scanState, name, title, body string) {
	body = strings.TrimSpace(body)
	if body == "" {
		return
	}
	key := name + "\x00" + title + "\x00" + body
	if _, exists := state.rawSet[key]; exists {
		return
	}
	state.rawSet[key] = struct{}{}
	state.report.Raw[name] = append(state.report.Raw[name], RawSnippet{Title: title, Body: body})
}

func parseYarnBlocks(content string) []struct {
	Keys      string
	Version   string
	Resolved  string
	Integrity string
} {
	type yarnBlock struct {
		Keys      string
		Version   string
		Resolved  string
		Integrity string
	}
	var blocks []yarnBlock
	var current *yarnBlock
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			if current != nil {
				blocks = append(blocks, *current)
				current = nil
			}
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			if current != nil {
				blocks = append(blocks, *current)
			}
			current = &yarnBlock{Keys: strings.TrimSuffix(line, ":")}
			continue
		}
		if current == nil {
			continue
		}
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "version "):
			current.Version = strings.Trim(strings.TrimPrefix(trimmed, "version "), `"`)
		case strings.HasPrefix(trimmed, "resolved "):
			current.Resolved = strings.Trim(strings.TrimPrefix(trimmed, "resolved "), `"`)
		case strings.HasPrefix(trimmed, "integrity "):
			current.Integrity = strings.TrimSpace(strings.TrimPrefix(trimmed, "integrity "))
		}
	}
	if current != nil {
		blocks = append(blocks, *current)
	}
	out := make([]struct {
		Keys      string
		Version   string
		Resolved  string
		Integrity string
	}, len(blocks))
	for i, block := range blocks {
		out[i] = struct {
			Keys      string
			Version   string
			Resolved  string
			Integrity string
		}(block)
	}
	return out
}

func packageNameFromPath(path, fallback string) string {
	if fallback != "" {
		return fallback
	}
	if path == "" {
		return ""
	}
	path = strings.TrimPrefix(path, "node_modules/")
	if idx := strings.LastIndex(path, "/node_modules/"); idx >= 0 {
		path = path[idx+len("/node_modules/"):]
	}
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "@") {
		parts := strings.Split(path, "/")
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
	}
	if idx := strings.Index(path, "/"); idx >= 0 {
		return path[:idx]
	}
	return path
}

func formatLockDetail(prefix, resolved, integrity string, hasInstallScript bool) string {
	parts := []string{prefix}
	if resolved != "" {
		parts = append(parts, "resolved="+resolved)
	}
	if integrity != "" {
		parts = append(parts, "integrity="+integrity)
	}
	if hasInstallScript {
		parts = append(parts, "hasInstallScript=true")
	}
	return strings.Join(parts, " ")
}

func exactVulnerableVersion(spec string) (string, bool) {
	trimmed := strings.TrimSpace(spec)
	trimmed = strings.TrimPrefix(trimmed, "=")
	version, err := semver.NewVersion(trimmed)
	if err != nil {
		return "", false
	}
	normalized := version.String()
	if isVulnerableAxiosVersion(normalized) {
		return normalized, true
	}
	return "", false
}

func semverRiskVersions(spec string) []string {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil
	}
	lower := strings.ToLower(trimmed)
	for _, prefix := range []string{"file:", "link:", "workspace:", "npm:", "git:", "git+", "github:", "http:", "https:"} {
		if strings.HasPrefix(lower, prefix) {
			return nil
		}
	}
	if lower == "latest" {
		return nil
	}
	if _, exact := exactVulnerableVersion(trimmed); exact {
		return nil
	}
	constraint, err := semver.NewConstraint(trimmed)
	if err != nil {
		return nil
	}
	var hits []string
	for _, versionText := range vulnerableAxiosVersions {
		version, err := semver.NewVersion(versionText)
		if err != nil {
			continue
		}
		if constraint.Check(version) {
			hits = append(hits, versionText)
		}
	}
	return hits
}

func compactJSON(data []byte) string {
	var out bytes.Buffer
	if err := json.Compact(&out, data); err != nil {
		return ""
	}
	return out.String()
}

func matchingLines(content string, needles []string, limit int) string {
	if limit <= 0 {
		return ""
	}
	var matches []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		for _, needle := range needles {
			if strings.Contains(line, needle) {
				matches = append(matches, line)
				break
			}
		}
		if len(matches) >= limit {
			break
		}
	}
	return strings.Join(matches, "\n")
}

func searchTreeForIndicators(root string, needles []string, limit int) string {
	if limit <= 0 {
		return ""
	}
	var matches []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if len(matches) >= limit {
			return io.EOF
		}
		bytes, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		snippet := matchingLines(string(bytes), needles, limit-len(matches))
		if snippet == "" {
			return nil
		}
		for _, line := range strings.Split(snippet, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			matches = append(matches, fmt.Sprintf("%s:%s", path, line))
			if len(matches) >= limit {
				return io.EOF
			}
		}
		return nil
	})
	return strings.Join(matches, "\n")
}

func readFirstLines(path string, limit int) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) >= limit {
			break
		}
	}
	return strings.Join(lines, "\n")
}

func fileSHA1(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	sum := sha1.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sum.Sum(nil)), nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sum.Sum(nil)), nil
}

func sanitizeField(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\t", " ")
	return strings.Join(strings.Fields(value), " ")
}

func boolToYesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func isVulnerableAxiosVersion(version string) bool {
	return version == "1.14.1" || version == "0.30.4"
}

func permissionDenied(output string) bool {
	output = strings.ToLower(output)
	return strings.Contains(output, "permission") || strings.Contains(output, "not permitted") || strings.Contains(output, "operation not allowed") || strings.Contains(output, "access is denied") || strings.Contains(output, "failed")
}

func (s *Scanner) env(key string) string {
	if value := s.cfg.Env[key]; value != "" {
		return value
	}
	return os.Getenv(key)
}
