package verdifax

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"
)

// ReproducibilityContext is the runtime a caller declares for a run.
// Every field is optional. The server records these values as given
// and does not check them.
type ReproducibilityContext struct {
	// Declared is true when any other field has a value. The client
	// derives it.
	Declared bool `json:"declared"`

	// ContainerImageHash is 64 hex characters, without the sha256:
	// prefix.
	ContainerImageHash string `json:"container_image_hash,omitempty"`

	RuntimeName    string `json:"runtime_name,omitempty"`
	RuntimeVersion string `json:"runtime_version,omitempty"`

	// PinnedDependencies holds sorted name==version strings.
	PinnedDependencies []string `json:"pinned_dependencies,omitempty"`

	GitCommitSHA string `json:"git_commit_sha,omitempty"`

	// RandomSeeds holds sorted library=seed strings.
	RandomSeeds []string `json:"random_seeds,omitempty"`

	// Platform is GOOS/GOARCH, for example linux/amd64.
	Platform string `json:"platform,omitempty"`
}

// withDeclaredFlag returns a copy of r with Declared derived.
func (r *ReproducibilityContext) withDeclaredFlag() *ReproducibilityContext {
	out := *r
	out.Declared = r.ContainerImageHash != "" || r.RuntimeName != "" || r.RuntimeVersion != "" ||
		len(r.PinnedDependencies) > 0 || r.GitCommitSHA != "" || len(r.RandomSeeds) > 0 || r.Platform != ""
	return &out
}

// CaptureOptions shapes CaptureEnvironment. A nil pointer captures
// everything it can.
type CaptureOptions struct {
	// DeclaredSeeds maps a library name to its seed. Recorded as
	// declared; the caller still has to apply the seeds.
	DeclaredSeeds map[string]string

	// SkipDependencies leaves out the modules built into this binary.
	SkipDependencies bool

	// SkipGit leaves out the result of git rev-parse HEAD.
	SkipGit bool

	// SkipContainer leaves out the container id from /proc/self/cgroup.
	SkipContainer bool
}

var (
	containerHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gitSHAPattern        = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

// CaptureEnvironment detects the running Go environment on a best-effort
// basis. A value that cannot be read is left out, and the server records
// it as not declared.
func CaptureEnvironment(opts *CaptureOptions) *ReproducibilityContext {
	if opts == nil {
		opts = &CaptureOptions{}
	}
	ctx := &ReproducibilityContext{
		Declared:       true,
		RuntimeName:    "go",
		RuntimeVersion: strings.TrimPrefix(runtime.Version(), "go"),
		Platform:       runtime.GOOS + "/" + runtime.GOARCH,
	}
	if !opts.SkipDependencies {
		ctx.PinnedDependencies = detectDependencies()
	}
	if !opts.SkipGit {
		ctx.GitCommitSHA = detectGitSHA()
	}
	if !opts.SkipContainer {
		ctx.ContainerImageHash = detectContainerHash()
	}
	for name, seed := range opts.DeclaredSeeds {
		ctx.RandomSeeds = append(ctx.RandomSeeds, fmt.Sprintf("%s=%s", name, seed))
	}
	sort.Strings(ctx.RandomSeeds)
	return ctx
}

func detectDependencies() []string {
	info, hasInfo := debug.ReadBuildInfo()
	if !hasInfo {
		return nil
	}
	pins := make([]string, 0, len(info.Deps))
	for _, dep := range info.Deps {
		pins = append(pins, dep.Path+"=="+dep.Version)
	}
	sort.Slice(pins, func(i, j int) bool { return strings.ToLower(pins[i]) < strings.ToLower(pins[j]) })
	return pins
}

func detectGitSHA() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, gitErr := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if gitErr != nil {
		return ""
	}
	sha := strings.ToLower(strings.TrimSpace(string(out)))
	if !gitSHAPattern.MatchString(sha) {
		return ""
	}
	return sha
}

func detectContainerHash() string {
	text, readErr := os.ReadFile("/proc/self/cgroup")
	if readErr != nil {
		return ""
	}
	return containerHashIn(string(text))
}

func containerHashIn(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		for _, segment := range strings.Split(line, "/") {
			if trimmed := strings.TrimSpace(segment); containerHashPattern.MatchString(trimmed) {
				return trimmed
			}
		}
	}
	return ""
}
