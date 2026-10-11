/*
Copyright The Helm Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package downloader

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	stdfs "io/fs"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"
	"sigs.k8s.io/yaml"

	"helm.sh/helm/v4/internal/resolver"
	"helm.sh/helm/v4/internal/third_party/dep/fs"
	"helm.sh/helm/v4/internal/urlutil"
	chart "helm.sh/helm/v4/pkg/chart/v2"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	chartutil "helm.sh/helm/v4/pkg/chart/v2/util"
	"helm.sh/helm/v4/pkg/getter"
	"helm.sh/helm/v4/pkg/helmpath"
	"helm.sh/helm/v4/pkg/registry"
	"helm.sh/helm/v4/pkg/repo/v1"
)

// ErrRepoNotFound indicates that chart repositories can't be found in local repo cache.
// The value of Repos is missing repos.
type ErrRepoNotFound struct {
	Repos []string
}

// Error implements the error interface.
func (e ErrRepoNotFound) Error() string {
	return "no repository definition for " + strings.Join(e.Repos, ", ")
}

const (
	// DefaultDownloadConcurrency is the conservative default upper bound on
	// how many dependencies are downloaded at the same time.
	DefaultDownloadConcurrency = 4

	// DefaultDownloadRetries is the default number of additional attempts made
	// after a transient download failure.
	DefaultDownloadRetries = 2

	// DefaultRetryInterval is the default amount of time waited between
	// download attempts.
	DefaultRetryInterval = 5 * time.Second
)

// DependencyStatus describes the outcome of processing a single dependency.
type DependencyStatus int

const (
	// DependencySucceeded indicates the dependency was downloaded, archived or
	// validated successfully.
	DependencySucceeded DependencyStatus = iota + 1
	// DependencySkipped indicates the dependency was satisfied by another
	// dependency referencing the same source and did not need downloading.
	DependencySkipped
	// DependencyFailed indicates the dependency could not be processed.
	DependencyFailed
	// DependencyNotStarted indicates processing was cancelled before the
	// dependency could start.
	DependencyNotStarted
)

// String returns a human readable status.
func (s DependencyStatus) String() string {
	switch s {
	case DependencySucceeded:
		return "succeeded"
	case DependencySkipped:
		return "skipped"
	case DependencyFailed:
		return "failed"
	case DependencyNotStarted:
		return "not started"
	default:
		return "unknown"
	}
}

// DependencyResult captures the outcome of processing one dependency.
type DependencyResult struct {
	// Name is the dependency chart name.
	Name string
	// Repository is the declared source: a repository URL, a file:// URL, or
	// empty for a chart expected in the charts directory.
	Repository string
	// Version is the requested version or version constraint.
	Version string
	// Status is the outcome.
	Status DependencyStatus
	// Reason is a short explanation for non-success statuses.
	Reason string
	// Err is the failure cause for DependencyFailed dependencies.
	Err error
}

// ErrDependencyDownloads aggregates the per-dependency results of a dependency
// download run. It is returned when at least one dependency failed or could
// not be started.
type ErrDependencyDownloads struct {
	// Results holds the result of every dependency in declaration order.
	Results []DependencyResult
}

// Failed returns the results of dependencies that failed or never started.
func (e *ErrDependencyDownloads) Failed() []DependencyResult {
	failed := []DependencyResult{}
	for _, r := range e.Results {
		if r.Status == DependencyFailed || r.Status == DependencyNotStarted {
			failed = append(failed, r)
		}
	}
	return failed
}

// Error implements the error interface.
//
// Every failed dependency is listed with its name, requested version,
// declared source and failure reason, even when only a single dependency
// failed.
func (e *ErrDependencyDownloads) Error() string {
	failed := e.Failed()
	var b strings.Builder
	fmt.Fprintf(&b, "failed to process %d chart %s:", len(failed), pluralDependency(len(failed)))
	for _, r := range failed {
		repository := r.Repository
		if repository == "" {
			repository = "(charts directory)"
		}
		reason := r.Reason
		if r.Err != nil {
			reason = r.Err.Error()
		}
		fmt.Fprintf(&b, "\n- %q version %q from %s: %s", r.Name, r.Version, repository, reason)
	}
	return b.String()
}

func pluralDependency(n int) string {
	if n == 1 {
		return "dependency"
	}
	return "dependencies"
}

// ErrRepositoryUpdates is returned when one or more chart repository indexes
// could not be updated.
type ErrRepositoryUpdates struct {
	// Results holds the result of every repository update in input order.
	Results []repo.UpdateResult
}

// NewRepositoryUpdateError builds an error from repository update results. It
// returns nil when every repository was updated successfully.
func NewRepositoryUpdateError(results []repo.UpdateResult) error {
	for _, r := range results {
		if r.Failed() {
			return &ErrRepositoryUpdates{Results: results}
		}
	}
	return nil
}

// Failed returns the per-repository failures, sorted by repository name for
// stable output.
func (e *ErrRepositoryUpdates) Failed() []repo.UpdateResult {
	failed := []repo.UpdateResult{}
	for _, r := range e.Results {
		if r.Failed() {
			failed = append(failed, r)
		}
	}
	sort.Slice(failed, func(i, j int) bool {
		if failed[i].Name != failed[j].Name {
			return failed[i].Name < failed[j].Name
		}
		return failed[i].URL < failed[j].URL
	})
	return failed
}

// AllFailed reports whether every attempted repository update failed.
func (e *ErrRepositoryUpdates) AllFailed() bool {
	return len(e.Results) > 0 && len(e.Failed()) == len(e.Results)
}

// Error implements the error interface.
func (e *ErrRepositoryUpdates) Error() string {
	failed := e.Failed()
	var b strings.Builder
	b.WriteString("failed to update the following repositories:")
	for _, r := range failed {
		fmt.Fprintf(&b, "\n\t- %q (%s): %v", r.Name, r.URL, r.Err)
	}
	return b.String()
}

// Manager handles the lifecycle of fetching, resolving, and storing dependencies.
type Manager struct {
	// Out is used to print warnings and notifications.
	Out io.Writer
	// ChartPath is the path to the unpacked base chart upon which this operates.
	ChartPath string
	// Verification indicates whether the chart should be verified.
	Verify VerificationStrategy
	// Debug is the global "--debug" flag
	Debug bool
	// Keyring is the key ring file.
	Keyring string
	// SkipUpdate indicates that the repository should not be updated first.
	SkipUpdate bool
	// Getter collection for the operation
	Getters          []getter.Provider
	RegistryClient   *registry.Client
	RepositoryConfig string
	RepositoryCache  string

	// ContentCache is a location where a cache of charts can be stored
	ContentCache string
	// SourceDateEpoch, when set, normalizes chart timestamps for reproducible archives.
	SourceDateEpoch *time.Time

	// Concurrency limits the number of dependencies downloaded in parallel.
	// Values below 1 fall back to DefaultDownloadConcurrency.
	Concurrency int
	// MaxRetries is the number of additional attempts made after a transient
	// download failure. Zero disables retries.
	MaxRetries int
	// RetryInterval is the time waited between download attempts. Values at or
	// below zero fall back to DefaultRetryInterval.
	RetryInterval time.Duration
	// Context is used to cancel dependency processing. When nil a background
	// context is used. After cancellation no further downloads are started.
	Context context.Context

	// outMu serializes writes to Out from concurrent workers.
	outMu sync.Mutex
}

// Build rebuilds a local charts directory from a lockfile.
//
// If the lockfile is not present, this will run a Manager.Update()
//
// If SkipUpdate is set, this will not update the repository.
func (m *Manager) Build() error {
	c, err := m.loadChartDir()
	if err != nil {
		return err
	}

	// If a lock file is found, run a build from that. Otherwise, just do
	// an update.
	lock := c.Lock
	if lock == nil {
		return m.Update()
	}

	// Check that all of the repos we're dependent on actually exist.
	req := c.Metadata.Dependencies

	// If using apiVersion v1, calculate the hash before resolve repo names
	// because resolveRepoNames will change req if req uses repo alias
	// and Helm 2 calculate the digest from the original req
	// Fix for: https://github.com/helm/helm/issues/7619
	var v2Sum string
	if c.Metadata.APIVersion == chart.APIVersionV1 {
		v2Sum, err = resolver.HashV2Req(req)
		if err != nil {
			return errors.New("the lock file (requirements.lock) is out of sync with the dependencies file (requirements.yaml). Please update the dependencies")
		}
	}

	if _, err := m.resolveRepoNames(req); err != nil {
		return err
	}

	if sum, err := resolver.HashReq(req, lock.Dependencies); err != nil || sum != lock.Digest {
		if c.Metadata.APIVersion != chart.APIVersionV1 {
			return errors.New("the lock file (Chart.lock) is out of sync with the dependencies file (Chart.yaml). Please update the dependencies with 'helm dependency update'")
		}
		// If lock digest differs and chart is apiVersion v1, it maybe because the lock was built
		// with Helm 2 and therefore should be checked with Helm v2 hash
		// Fix for: https://github.com/helm/helm/issues/7233
		log.Println("warning: a valid Helm v3 hash was not found. Checking against Helm v2 hash...")
		if v2Sum != lock.Digest {
			return errors.New("the lock file (requirements.lock) is out of sync with the dependencies file (requirements.yaml). Please update the dependencies")
		}
	}

	// Check that all of the repos we're dependent on actually exist.
	if err := m.hasAllRepos(lock.Dependencies); err != nil {
		return err
	}

	var errs []error
	if !m.SkipUpdate {
		// For each repo in the file, update the cached copy of that repo.
		// Partial repository update failures are collected rather than
		// aborting, as cached indexes may still satisfy the build.
		if err := m.UpdateRepositories(); err != nil {
			errs = append(errs, err)
		}
	}

	// Now we need to fetch every package here into charts/. Successful
	// downloads are moved into charts/ even when another dependency fails.
	if err := m.downloadAll(lock.Dependencies); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Update updates a local charts directory.
//
// It first reads the Chart.yaml file, and then attempts to
// negotiate versions based on that. It will download the versions
// from remote chart repositories unless SkipUpdate is true.
func (m *Manager) Update() error {
	ctx := m.context()

	c, err := m.loadChartDir()
	if err != nil {
		return err
	}

	// If no dependencies are found, we consider this a successful
	// completion.
	req := c.Metadata.Dependencies
	if req == nil {
		return nil
	}

	var errs []error

	// Get the names of the repositories the dependencies need that Helm is
	// configured to know about.
	repoNames, err := m.resolveRepoNames(req)
	if err != nil {
		return err
	}

	// For the repositories Helm is not configured to know about, ensure Helm
	// has some information about them and, when possible, the index files
	// locally.
	//
	// TODO Helm v5: require users to add repositories explicitly rather than
	// adding them automatically. They should have to add them in order to make
	// sure they are aware of the repositories and opt-in to any locations, for
	// security.
	repoNames, err = m.ensureMissingRepos(ctx, repoNames, req)
	if err != nil {
		errs = append(errs, err)
	}

	// For each of the repositories Helm is configured to know about, update
	// the index information locally. Partial failures do not prevent the
	// cached indexes from being used; they are reported in the final error.
	if !m.SkipUpdate {
		if err := m.UpdateRepositories(); err != nil {
			errs = append(errs, err)
		}
	}

	// Now we need to find out which version of a chart best satisfies the
	// dependencies in the Chart.yaml
	lock, err := m.resolve(req, repoNames)
	if err != nil {
		errs = append(errs, err)
		return errors.Join(errs...)
	}

	// Now we need to fetch every package here into charts/. A failure for
	// one dependency does not stop the remaining dependencies from being
	// downloaded and moved into charts/.
	if err := m.downloadAll(lock.Dependencies); err != nil {
		// Downloads are incomplete: keep the existing lock file, but still
		// surface any repository update failures.
		errs = append(errs, err)
		return errors.Join(errs...)
	}

	// downloadAll might overwrite dependency version, recalculate lock digest
	newDigest, err := resolver.HashReq(req, lock.Dependencies)
	if err != nil {
		errs = append(errs, err)
		return errors.Join(errs...)
	}
	lock.Digest = newDigest

	// If the lock file hasn't changed, don't write a new one.
	oldLock := c.Lock
	if oldLock == nil || oldLock.Digest != lock.Digest {
		// Finally, we need to write the lockfile.
		if err := writeLock(m.ChartPath, lock, c.Metadata.APIVersion == chart.APIVersionV1); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// context returns the context used for cancellable processing.
func (m *Manager) context() context.Context {
	if m.Context != nil {
		return m.Context
	}
	return context.Background()
}

// logf serializes writes to Out so concurrent workers do not interleave.
func (m *Manager) logf(format string, args ...any) {
	m.outMu.Lock()
	defer m.outMu.Unlock()
	fmt.Fprintf(m.Out, format, args...)
}

// synchronizedWriter wraps an io.Writer serializing concurrent writes using
// the Manager's output mutex.
func (m *Manager) synchronizedWriter() io.Writer {
	return &mutexWriter{w: m.Out, mu: &m.outMu}
}

type mutexWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l *mutexWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// downloadConcurrency returns the configured parallelism or the default.
func (m *Manager) downloadConcurrency() int {
	if m.Concurrency > 0 {
		return m.Concurrency
	}
	return DefaultDownloadConcurrency
}

// maxAttempts returns the total number of download attempts (the initial
// attempt plus retries).
func (m *Manager) maxAttempts() int {
	if m.MaxRetries < 0 {
		return DefaultDownloadRetries + 1
	}
	return m.MaxRetries + 1
}

// retryInterval returns the configured retry interval or the default.
func (m *Manager) retryInterval() time.Duration {
	if m.RetryInterval > 0 {
		return m.RetryInterval
	}
	return DefaultRetryInterval
}

func (m *Manager) loadChartDir() (*chart.Chart, error) {
	if fi, err := os.Stat(m.ChartPath); err != nil {
		return nil, fmt.Errorf("could not find %s: %w", m.ChartPath, err)
	} else if !fi.IsDir() {
		return nil, errors.New("only unpacked charts can be updated")
	}
	return loader.LoadDir(m.ChartPath)
}

// resolve takes a list of dependencies and translates them into an exact version to download.
//
// This returns a lock file, which has all of the dependencies normalized to a specific version.
func (m *Manager) resolve(req []*chart.Dependency, repoNames map[string]string) (*chart.Lock, error) {
	res := resolver.New(m.ChartPath, m.RepositoryCache, m.RegistryClient)
	return res.Resolve(req, repoNames)
}

// downloadAll takes a list of dependencies and downloads them into charts/
//
// Dependencies are processed with bounded concurrency (see Manager.Concurrency)
// and each one is recorded independently: a failure for one dependency does
// not stop the remaining dependencies from being downloaded and moved into
// charts/. Dependencies that resolve to the same source are downloaded once.
// Transient download failures are retried (see Manager.MaxRetries).
//
// It will delete versions of the chart that exist on disk and might cause
// a conflict.
func (m *Manager) downloadAll(deps []*chart.Dependency) error {
	ctx := m.context()

	repos, err := m.loadChartRepositories()
	if err != nil {
		return err
	}

	destPath := filepath.Join(m.ChartPath, "charts")

	// Check if 'charts' directory is not actually a directory. If it does not exist, create it.
	if fi, err := os.Stat(destPath); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%q is not a directory", destPath)
		}
	} else if errors.Is(err, stdfs.ErrNotExist) {
		if err := os.MkdirAll(destPath, 0o755); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("unable to retrieve file info for '%s': %w", destPath, err)
	}

	// Use a unique temp directory per invocation so repeated updates within the
	// same process (and concurrent updates) cannot interfere with each other.
	tmpPath, err := os.MkdirTemp(m.ChartPath, "tmpcharts-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpPath)

	fmt.Fprintf(m.Out, "Saving %d charts\n", len(deps))

	results := make([]DependencyResult, len(deps))
	for i, dep := range deps {
		results[i] = DependencyResult{
			Name:       dep.Name,
			Repository: dep.Repository,
			Version:    dep.Version,
			Status:     DependencyNotStarted,
			Reason:     "download did not start",
		}
	}

	jobs := &dependencyJobs{
		m:        m,
		out:      m.synchronizedWriter(),
		repos:    repos,
		tmpPath:  tmpPath,
		destPath: destPath,
		remote:   map[string]*downloadSlot{},
		archived: map[string]*downloadSlot{},
	}

	concurrency := min(m.downloadConcurrency(), len(deps))
	// A semaphore bounds the number of in-flight dependencies. Workers are
	// launched in dependency declaration order, so with concurrency one the
	// output ordering is identical to a purely sequential run.
	sem := make(chan struct{}, concurrency)

	var wg sync.WaitGroup
submission:
	for i, dep := range deps {
		// Do not start anything new when the context is already cancelled.
		select {
		case <-ctx.Done():
			for j := i; j < len(deps); j++ {
				results[j] = notStartedResult(deps[j], ctx.Err())
			}
			break submission
		default:
		}

		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			// Cancellation: leave every dependency that has not been handed
			// to a worker marked as not started and launch nothing new.
			for j := i; j < len(deps); j++ {
				results[j] = notStartedResult(deps[j], ctx.Err())
			}
			break submission
		}

		wg.Add(1)
		go func(i int, dep *chart.Dependency) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = jobs.process(ctx, dep)
		}(i, dep)
	}
	wg.Wait()

	// On cancellation publish nothing: leave charts/ untouched and let the
	// deferred cleanup remove the temp directory so no half-finished
	// artifacts remain.
	if ctx.Err() != nil {
		for i := range results {
			if results[i].Status == DependencyNotStarted && results[i].Err == nil {
				results[i] = notStartedResult(deps[i], ctx.Err())
			}
		}
		return newDependencyDownloadsError(results)
	}

	// Move all successfully downloaded charts to destPath and delete outdated
	// dependencies. This runs even when some dependencies failed so successful
	// downloads can be reused by the next run.
	if err := m.safeMoveDeps(results, deps, tmpPath, destPath); err != nil {
		return err
	}

	if dlErr := newDependencyDownloadsError(results); dlErr != nil {
		fmt.Fprintf(m.Out, "Save error occurred:  %s\n", dlErr)
		return dlErr
	}
	return nil
}

// newDependencyDownloadsError builds an aggregate error from per-dependency
// results, or returns nil when every dependency succeeded or was skipped.
func newDependencyDownloadsError(results []DependencyResult) error {
	for _, r := range results {
		if r.Status == DependencyFailed || r.Status == DependencyNotStarted {
			return &ErrDependencyDownloads{Results: results}
		}
	}
	return nil
}

// notStartedResult records a dependency that was not handed to a worker,
// typically because processing was cancelled.
func notStartedResult(dep *chart.Dependency, cause error) DependencyResult {
	return DependencyResult{
		Name:       dep.Name,
		Repository: dep.Repository,
		Version:    dep.Version,
		Status:     DependencyNotStarted,
		Reason:     "canceled before the download started",
		Err:        fmt.Errorf("dependency %q was not started: %w", dep.Name, cause),
	}
}

// downloadSlot coordinates dependencies that resolve to the same source. The
// first dependency (the leader) performs the work; followers wait for its
// outcome instead of downloading again.
type downloadSlot struct {
	done    chan struct{}
	result  DependencyResult
	version string
}

// dependencyJobs runs the per-dependency download pipeline for a single
// downloadAll invocation.
type dependencyJobs struct {
	m                 *Manager
	out               io.Writer
	repos             map[string]*repo.ChartRepository
	tmpPath, destPath string
	mu                sync.Mutex
	remote            map[string]*downloadSlot
	archived          map[string]*downloadSlot
}

// acquire returns the slot for the given key and whether it already existed.
func (j *dependencyJobs) acquire(table map[string]*downloadSlot, key string) (*downloadSlot, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if s, ok := table[key]; ok {
		return s, true
	}
	s := &downloadSlot{done: make(chan struct{})}
	table[key] = s
	return s, false
}

// process handles one dependency and records its result.
func (j *dependencyJobs) process(ctx context.Context, dep *chart.Dependency) DependencyResult {
	switch {
	case dep.Repository == "":
		// No repository means the chart is expected in the charts directory.
		return j.processLocal(dep)
	case strings.HasPrefix(dep.Repository, "file://"):
		return j.processArchive(ctx, dep)
	default:
		return j.processRemote(ctx, dep)
	}
}

// resultFor builds the base result for a dependency. The requested version is
// recorded before processing may normalize it (e.g. by archiving a local
// chart satisfying a range constraint).
func resultFor(dep *chart.Dependency, requestedVersion string, status DependencyStatus, reason string, err error) DependencyResult {
	return DependencyResult{
		Name:       dep.Name,
		Repository: dep.Repository,
		Version:    requestedVersion,
		Status:     status,
		Reason:     reason,
		Err:        err,
	}
}

// processLocal validates a chart expected to already exist as a directory in
// charts/.
func (j *dependencyJobs) processLocal(dep *chart.Dependency) DependencyResult {
	requested := dep.Version
	j.m.logf("Dependency %s did not declare a repository. Assuming it exists in the charts directory\n", dep.Name)
	// NOTE: we are only validating the local dependency conforms to the
	// constraints. No copying to tmpPath is necessary.
	chartPath := filepath.Join(j.destPath, dep.Name)
	ch, err := loader.LoadDir(chartPath)
	if err != nil {
		return resultFor(dep, requested, DependencyFailed, "", fmt.Errorf("unable to load chart '%s': %w", chartPath, err))
	}

	constraint, err := semver.NewConstraint(dep.Version)
	if err != nil {
		return resultFor(dep, requested, DependencyFailed, "", fmt.Errorf("dependency %s has an invalid version/constraint format: %w", dep.Name, err))
	}

	v, err := semver.NewVersion(ch.Metadata.Version)
	if err != nil {
		return resultFor(dep, requested, DependencyFailed, "", fmt.Errorf("invalid version %s for dependency %s: %w", dep.Version, dep.Name, err))
	}

	if !constraint.Check(v) {
		return resultFor(dep, requested, DependencyFailed, "",
			fmt.Errorf("dependency %s at version %s does not satisfy the constraint %s", dep.Name, ch.Metadata.Version, dep.Version))
	}
	return resultFor(dep, requested, DependencySucceeded, "", nil)
}

// processArchive archives a file:// dependency into the temp directory.
func (j *dependencyJobs) processArchive(_ context.Context, dep *chart.Dependency) DependencyResult {
	requested := dep.Version
	if j.m.Debug {
		j.m.logf("Archiving %s from repo %s\n", dep.Name, dep.Repository)
	}

	slot, existed := j.acquire(j.archived, dep.Repository+"|"+dep.Name)
	if existed {
		return j.awaitSlot(slot, dep, requested)
	}

	ver, err := tarFromLocalDir(j.m.ChartPath, dep.Name, dep.Repository, dep.Version, j.tmpPath, j.m.SourceDateEpoch)
	if err != nil {
		res := resultFor(dep, requested, DependencyFailed, "", err)
		slot.result = res
		close(slot.done)
		return res
	}
	dep.Version = ver
	slot.version = ver
	res := resultFor(dep, requested, DependencySucceeded, "", nil)
	slot.result = res
	close(slot.done)
	return res
}

// processRemote resolves and downloads a repository or OCI dependency.
func (j *dependencyJobs) processRemote(ctx context.Context, dep *chart.Dependency) DependencyResult {
	requested := dep.Version

	// Any failure to resolve/download a chart should fail:
	// https://github.com/helm/helm/issues/1439
	churl, username, password, insecureSkipTLSVerify, passCredentialsAll, caFile, certFile, keyFile, err :=
		j.m.findChartURL(dep.Name, dep.Version, dep.Repository, j.repos)
	if err != nil {
		return resultFor(dep, requested, DependencyFailed, "", fmt.Errorf("could not find %s: %w", churl, err))
	}

	version := ""
	isOCI := registry.IsOCI(churl)
	if isOCI {
		churl, version, err = parseOCIRef(churl)
		if err != nil {
			return resultFor(dep, requested, DependencyFailed, "", fmt.Errorf("could not parse OCI reference: %w", err))
		}
	}

	slot, existed := j.acquire(j.remote, churl)
	if existed {
		return j.awaitSlot(slot, dep, requested)
	}

	j.m.logf("Downloading %s from repo %s\n", dep.Name, dep.Repository)

	dl := ChartDownloader{
		Out:              j.out,
		Verify:           j.m.Verify,
		Keyring:          j.m.Keyring,
		RepositoryConfig: j.m.RepositoryConfig,
		RepositoryCache:  j.m.RepositoryCache,
		ContentCache:     j.m.ContentCache,
		RegistryClient:   j.m.RegistryClient,
		Getters:          j.m.Getters,
		Options: []getter.Option{
			getter.WithBasicAuth(username, password),
			getter.WithPassCredentialsAll(passCredentialsAll),
			getter.WithInsecureSkipVerifyTLS(insecureSkipTLSVerify),
			getter.WithTLSClientConfig(certFile, keyFile, caFile),
		},
	}
	if isOCI {
		dl.Options = append(dl.Options,
			getter.WithRegistryClient(j.m.RegistryClient),
			getter.WithTagName(version))
	}

	if err := j.m.downloadToWithRetry(ctx, &dl, churl, version, j.tmpPath, dep.Name); err != nil {
		res := resultFor(dep, requested, DependencyFailed, "", fmt.Errorf("could not download %s: %w", churl, err))
		slot.result = res
		close(slot.done)
		return res
	}

	res := resultFor(dep, requested, DependencySucceeded, "", nil)
	slot.result = res
	close(slot.done)
	return res
}

// awaitSlot waits for a leader slot and reports the dependency as skipped when
// the shared source was already handled successfully.
func (j *dependencyJobs) awaitSlot(slot *downloadSlot, dep *chart.Dependency, requestedVersion string) DependencyResult {
	<-slot.done
	j.m.logf("Already downloaded %s from repo %s\n", dep.Name, dep.Repository)
	if slot.version != "" {
		dep.Version = slot.version
	}
	if slot.result.Status != DependencySucceeded {
		return resultFor(dep, requestedVersion, DependencyFailed, "",
			fmt.Errorf("shared source download failed: %w", slot.result.Err))
	}
	return resultFor(dep, requestedVersion, DependencySkipped, "already downloaded from the same source", nil)
}

// downloadToWithRetry downloads a chart, retrying transient failures a bounded
// number of times with a fixed interval. Deterministic failures (resolution,
// verification, HTTP client errors other than 429/5xx) are not retried, so the
// existing cache, digest and provenance rules remain unchanged.
func (m *Manager) downloadToWithRetry(ctx context.Context, dl *ChartDownloader, ref, version, dest, name string) error {
	maxAttempts := m.maxAttempts()
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			m.logf("Warning: download of %s failed: %v. Retrying in %s (attempt %d/%d).\n",
				name, err, m.retryInterval(), attempt, maxAttempts)
			select {
			case <-time.After(m.retryInterval()):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		// DownloadTo is not context-aware; cancellation is honored around
		// this call (no new downloads start, retry backoffs are interrupted).
		if _, _, err = dl.DownloadTo(ref, version, dest); err == nil { //nolint:contextcheck
			return nil
		}

		// Do not retry on cancellation or non-transient errors; do not retry
		// once all attempts are spent.
		if ctx.Err() != nil || !isRetryableDownloadError(err) || attempt == maxAttempts {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
	}
	return err
}

func parseOCIRef(chartRef string) (string, string, error) {
	refTagRegexp := regexp.MustCompile(`^(oci://[^:]+(:\d{1,5})?[^:]+):(.*)$`)
	caps := refTagRegexp.FindStringSubmatch(chartRef)
	if len(caps) != 4 {
		return "", "", fmt.Errorf("improperly formatted oci chart reference: %s", chartRef)
	}
	chartRef = caps[1]
	tag := caps[3]

	return chartRef, tag, nil
}

// safeMoveDeps moves all dependencies in the source and moves them into dest.
//
// It does this by first matching the file name to an expected pattern, then loading
// the file to verify that it is a chart.
//
// Any charts in dest that do not exist in source are removed (barring local
// dependencies and dependencies that were not updated successfully during this
// run, whose previous artifacts are preserved for the next run to reuse)
//
// Because it requires tar file introspection, it is more intensive than a basic move.
//
// This will only return errors that should stop processing entirely. Other errors
// will emit log messages or be ignored.
func (m *Manager) safeMoveDeps(results []DependencyResult, deps []*chart.Dependency, source, dest string) error {
	existsInSourceDirectory := map[string]bool{}
	isLocalDependency := map[string]bool{}
	statusByName := map[string]DependencyStatus{}
	sourceFiles, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	// attempt to read destFiles; fail fast if we can't
	destFiles, err := os.ReadDir(dest)
	if err != nil {
		return err
	}

	for _, dep := range deps {
		if dep.Repository == "" {
			isLocalDependency[dep.Name] = true
		}
	}
	for _, r := range results {
		// When a name appears more than once (same source referenced by
		// several dependencies) a successful result keeps cleanup active.
		if r.Status == DependencySucceeded || r.Status == DependencySkipped {
			statusByName[r.Name] = DependencySucceeded
		} else if _, ok := statusByName[r.Name]; !ok {
			statusByName[r.Name] = r.Status
		}
	}

	for _, file := range sourceFiles {
		if file.IsDir() {
			continue
		}
		filename := file.Name()
		sourcefile := filepath.Join(source, filename)
		destfile := filepath.Join(dest, filename)
		existsInSourceDirectory[filename] = true
		if _, err := loader.LoadFile(sourcefile); err != nil {
			fmt.Fprintf(m.Out, "Could not verify %s for moving: %s (Skipping)", sourcefile, err)
			continue
		}
		// NOTE: no need to delete the dest; os.Rename replaces it.
		if err := fs.RenameWithFallback(sourcefile, destfile); err != nil {
			fmt.Fprintf(m.Out, "Unable to move %s to charts dir %s (Skipping)", sourcefile, err)
			continue
		}
	}

	fmt.Fprintln(m.Out, "Deleting outdated charts")
	// find all files that exist in dest that do not exist in source; delete them (outdated dependencies)
	for _, file := range destFiles {
		if file.IsDir() || existsInSourceDirectory[file.Name()] {
			continue
		}
		fname := filepath.Join(dest, file.Name())
		ch, err := loader.LoadFile(fname)
		if err != nil {
			fmt.Fprintf(m.Out, "Could not verify %s for deletion: %s (Skipping)\n", fname, err)
			continue
		}
		// local dependency - skip
		if isLocalDependency[ch.Name()] {
			continue
		}
		// The dependency failed or was never started in this run: keep the
		// previously downloaded artifact so a later run can reuse it.
		if status, known := statusByName[ch.Name()]; known && status != DependencySucceeded {
			continue
		}
		if err := os.Remove(fname); err != nil {
			fmt.Fprintf(m.Out, "Could not delete %s: %s (Skipping)", fname, err)
			continue
		}
	}

	return nil
}

// hasAllRepos ensures that all of the referenced deps are in the local repo cache.
func (m *Manager) hasAllRepos(deps []*chart.Dependency) error {
	rf, err := loadRepoConfig(m.RepositoryConfig)
	if err != nil {
		return err
	}
	repos := rf.Repositories

	// Verify that all repositories referenced in the deps are actually known
	// by Helm.
	missing := []string{}
Loop:
	for _, dd := range deps {
		// If repo is from local path or OCI, continue
		if strings.HasPrefix(dd.Repository, "file://") || registry.IsOCI(dd.Repository) {
			continue
		}

		if dd.Repository == "" {
			continue
		}
		for _, repo := range repos {
			if urlutil.Equal(repo.URL, strings.TrimSuffix(dd.Repository, "/")) {
				continue Loop
			}
		}
		missing = append(missing, dd.Repository)
	}
	if len(missing) > 0 {
		return ErrRepoNotFound{missing}
	}
	return nil
}

// ensureMissingRepos attempts to ensure the repository information for repos
// not managed by Helm is present. This takes in the repoNames Helm is configured
// to work with along with the chart dependencies. It will find the deps not
// in a known repo and attempt to ensure the data is present for steps like
// version resolution.
func (m *Manager) ensureMissingRepos(ctx context.Context, repoNames map[string]string, deps []*chart.Dependency) (map[string]string, error) {
	var ru []*repo.Entry

	for _, dd := range deps {
		// If the chart is in the local charts directory no repository needs
		// to be specified.
		if dd.Repository == "" {
			continue
		}

		// When the repoName for a dependency is known we can skip ensuring
		if _, ok := repoNames[dd.Name]; ok {
			continue
		}

		// The generated repository name, which will result in an index being
		// locally cached, has a name pattern of "helm-manager-" followed by a
		// sha256 of the repo name. This assumes end users will never create
		// repositories with these names pointing to other repositories. Using
		// this method of naming allows the existing repository pulling and
		// resolution code to do most of the work.
		rn, err := key(dd.Repository)
		if err != nil {
			return repoNames, err
		}
		rn = managerKeyPrefix + rn

		repoNames[dd.Name] = rn

		// Assuming the repository is generally available. For Helm managed
		// access controls the repository needs to be added through the user
		// managed system. This path will work for public charts, like those
		// supplied by Bitnami, but not for protected charts, like corp ones
		// behind a username and pass.
		ri := &repo.Entry{
			Name: rn,
			URL:  dd.Repository,
		}
		ru = append(ru, ri)
	}

	// Calls to UpdateRepositories (a public function) will only update
	// repositories configured by the user. Here we update repos found in
	// the dependencies that are not known to the user if update skipping
	// is not configured. Failures are returned as structured per-repository
	// results but do not prevent the caller from using cached indexes.
	if !m.SkipUpdate && len(ru) > 0 {
		m.logf("Getting updates for unmanaged Helm repositories...\n")
		if err := NewRepositoryUpdateError(m.parallelRepoUpdate(ctx, ru)); err != nil {
			return repoNames, err
		}
	}

	return repoNames, nil
}

// resolveRepoNames returns the repo names of the referenced deps which can be used to fetch the cached index file
// and replaces aliased repository URLs into resolved URLs in dependencies.
func (m *Manager) resolveRepoNames(deps []*chart.Dependency) (map[string]string, error) {
	rf, err := loadRepoConfig(m.RepositoryConfig)
	if err != nil {
		if errors.Is(err, stdfs.ErrNotExist) {
			return make(map[string]string), nil
		}
		return nil, err
	}
	repos := rf.Repositories

	reposMap := make(map[string]string)

	// Verify that all repositories referenced in the deps are actually known
	// by Helm.
	missing := []string{}
	for _, dd := range deps {
		// Don't map the repository, we don't need to download chart from charts directory
		if dd.Repository == "" {
			continue
		}
		// if dep chart is from local path, verify the path is valid
		if strings.HasPrefix(dd.Repository, "file://") {
			if _, err := resolver.GetLocalPath(dd.Repository, m.ChartPath); err != nil {
				return nil, err
			}

			if m.Debug {
				fmt.Fprintf(m.Out, "Repository from local path: %s\n", dd.Repository)
			}
			reposMap[dd.Name] = dd.Repository
			continue
		}

		if registry.IsOCI(dd.Repository) {
			reposMap[dd.Name] = dd.Repository
			continue
		}

		found := false

		for _, repo := range repos {
			if (strings.HasPrefix(dd.Repository, "@") && strings.TrimPrefix(dd.Repository, "@") == repo.Name) ||
				(strings.HasPrefix(dd.Repository, "alias:") && strings.TrimPrefix(dd.Repository, "alias:") == repo.Name) {
				found = true
				dd.Repository = repo.URL
				reposMap[dd.Name] = repo.Name
				break
			} else if urlutil.Equal(repo.URL, dd.Repository) {
				found = true
				reposMap[dd.Name] = repo.Name
				break
			}
		}
		if !found {
			repository := dd.Repository
			// Add if URL
			_, err := url.ParseRequestURI(repository)
			if err == nil {
				reposMap[repository] = repository
				continue
			}
			missing = append(missing, repository)
		}
	}
	if len(missing) > 0 {
		errorMessage := fmt.Sprintf("no repository definition for %s. Please add them via 'helm repo add'", strings.Join(missing, ", "))
		// It is common for people to try to enter "stable" as a repository instead of the actual URL.
		// For this case, let's give them a suggestion.
		containsNonURL := false
		for _, repo := range missing {
			if !strings.Contains(repo, "//") && !strings.HasPrefix(repo, "@") && !strings.HasPrefix(repo, "alias:") {
				containsNonURL = true
			}
		}
		if containsNonURL {
			errorMessage += `
Note that repositories must be URLs or aliases. For example, to refer to the "example"
repository, use "https://charts.example.com/" or "@example" instead of
"example". Don't forget to add the repo, too ('helm repo add').`
		}
		return nil, errors.New(errorMessage)
	}
	return reposMap, nil
}

// UpdateRepositories updates all of the local repos to the latest.
//
// Every repository is attempted. The returned error is nil on full success
// and otherwise an *ErrRepositoryUpdates with a structured result for each
// repository, so partial and total failures can be distinguished by the
// caller.
func (m *Manager) UpdateRepositories() error {
	rf, err := loadRepoConfig(m.RepositoryConfig)
	if err != nil {
		return err
	}
	repos := rf.Repositories
	if len(repos) > 0 {
		m.logf("Hang tight while we grab the latest from your chart repositories...\n")
		results := m.parallelRepoUpdate(m.context(), repos)
		if updateErr := NewRepositoryUpdateError(results); updateErr != nil {
			return updateErr
		}
		m.logf("Update Complete. ⎈Happy Helming!⎈\n")
	}
	return nil
}

// Filter out duplicate repos by URL, including those with trailing slashes.
// Input order is preserved; on a duplicate the last entry wins.
func dedupeRepos(repos []*repo.Entry) []*repo.Entry {
	index := make(map[string]int)
	var unique []*repo.Entry
	for _, r := range repos {
		// Normalize URL by removing trailing slashes.
		seenURL := strings.TrimSuffix(r.URL, "/")
		if pos, ok := index[seenURL]; ok {
			unique[pos] = r // last one wins
			continue
		}
		index[seenURL] = len(unique)
		unique = append(unique, r)
	}
	return unique
}

// parallelRepoUpdate updates the index files of the given repositories
// concurrently and returns a structured result for each of them, in input
// order. A failure for one repository does not prevent the others from being
// updated. After ctx is cancelled no new update is started.
func (m *Manager) parallelRepoUpdate(ctx context.Context, repos []*repo.Entry) []repo.UpdateResult {
	localRepos := dedupeRepos(repos)
	results := make([]repo.UpdateResult, len(localRepos))

	var wg sync.WaitGroup
	for i, c := range localRepos {
		if err := ctx.Err(); err != nil {
			results[i] = repo.UpdateResult{Name: c.Name, URL: c.URL, Err: err}
			continue
		}

		r, err := repo.NewChartRepository(c, m.Getters)
		if err != nil {
			results[i] = repo.UpdateResult{Name: c.Name, URL: c.URL, Err: err}
			continue
		}
		r.CachePath = m.RepositoryCache

		wg.Add(1)
		go func(i int, r *repo.ChartRepository) {
			defer wg.Done()
			_, err := r.DownloadIndexFile()
			if err != nil {
				// For those dependencies that are not known to helm and using a
				// generated key name we display the repo url.
				if strings.HasPrefix(r.Config.Name, managerKeyPrefix) {
					m.logf("...Unable to get an update from the %q chart repository:\n\t%s\n", r.Config.URL, err)
				} else {
					m.logf("...Unable to get an update from the %q chart repository (%s):\n\t%s\n", r.Config.Name, r.Config.URL, err)
				}
			} else {
				// For those dependencies that are not known to helm and using a
				// generated key name we display the repo url.
				if strings.HasPrefix(r.Config.Name, managerKeyPrefix) {
					m.logf("...Successfully got an update from the %q chart repository\n", r.Config.URL)
				} else {
					m.logf("...Successfully got an update from the %q chart repository\n", r.Config.Name)
				}
			}
			results[i] = repo.UpdateResult{Name: r.Config.Name, URL: r.Config.URL, Err: err}
		}(i, r)
	}
	wg.Wait()

	return results
}

// findChartURL searches the cache of repo data for a chart that has the name and the repoURL specified.
//
// 'name' is the name of the chart. Version is an exact semver, or an empty string. If empty, the
// newest version will be returned.
//
// repoURL is the repository to search
//
// If it finds a URL that is "relative", it will prepend the repoURL.
func (m *Manager) findChartURL(name, version, repoURL string, repos map[string]*repo.ChartRepository) (url, username, password string, insecureSkipTLSVerify, passCredentialsAll bool, caFile, certFile, keyFile string, err error) {
	if registry.IsOCI(repoURL) {
		return fmt.Sprintf("%s/%s:%s", repoURL, name, version), "", "", false, false, "", "", "", nil
	}

	for _, cr := range repos {
		if !urlutil.Equal(repoURL, cr.Config.URL) {
			continue
		}
		var entry repo.ChartVersions
		entry, err = findEntryByName(name, cr)
		if err != nil {
			// TODO: Consider refactoring this function to reduce the number of returned values while preserving behavior.
			return url, username, password, insecureSkipTLSVerify, passCredentialsAll, caFile, certFile, keyFile, err
		}
		var ve *repo.ChartVersion
		ve, err = findVersionedEntry(version, entry)
		if err != nil {
			return url, username, password, insecureSkipTLSVerify, passCredentialsAll, caFile, certFile, keyFile, err
		}
		url, err = repo.ResolveReferenceURL(repoURL, ve.URLs[0])
		if err != nil {
			return url, username, password, insecureSkipTLSVerify, passCredentialsAll, caFile, certFile, keyFile, err
		}
		username = cr.Config.Username
		password = cr.Config.Password
		passCredentialsAll = cr.Config.PassCredentialsAll
		insecureSkipTLSVerify = cr.Config.InsecureSkipTLSVerify
		caFile = cr.Config.CAFile
		certFile = cr.Config.CertFile
		keyFile = cr.Config.KeyFile

		return url, username, password, insecureSkipTLSVerify, passCredentialsAll, caFile, certFile, keyFile, err
	}
	url, err = repo.FindChartInRepoURL(repoURL, name, m.Getters, repo.WithChartVersion(version), repo.WithClientTLS(certFile, keyFile, caFile))
	if err == nil {
		return url, username, password, false, false, "", "", "", nil
	}
	err = fmt.Errorf("chart %s not found in %s: %w", name, repoURL, err)
	return url, username, password, false, false, "", "", "", err
}

// findEntryByName finds an entry in the chart repository whose name matches the given name.
//
// It returns the ChartVersions for that entry.
func findEntryByName(name string, cr *repo.ChartRepository) (repo.ChartVersions, error) {
	for ename, entry := range cr.IndexFile.Entries {
		if ename == name {
			return entry, nil
		}
	}
	return nil, errors.New("entry not found")
}

// findVersionedEntry takes a ChartVersions list and returns a single chart version that satisfies the version constraints.
//
// If version is empty, the first chart found is returned.
func findVersionedEntry(version string, vers repo.ChartVersions) (*repo.ChartVersion, error) {
	for _, verEntry := range vers {
		if len(verEntry.URLs) == 0 {
			// Not a legit entry.
			continue
		}

		if version == "" || versionEquals(version, verEntry.Version) {
			return verEntry, nil
		}
	}
	return nil, errors.New("no matching version")
}

func versionEquals(v1, v2 string) bool {
	sv1, err := semver.NewVersion(v1)
	if err != nil {
		// Fallback to string comparison.
		return v1 == v2
	}
	sv2, err := semver.NewVersion(v2)
	if err != nil {
		return false
	}
	return sv1.Equal(sv2)
}

// loadChartRepositories reads the repositories.yaml, and then builds a map of
// ChartRepositories.
//
// The key is the local name (which is only present in the repositories.yaml).
func (m *Manager) loadChartRepositories() (map[string]*repo.ChartRepository, error) {
	indices := map[string]*repo.ChartRepository{}

	// Load repositories.yaml file
	rf, err := loadRepoConfig(m.RepositoryConfig)
	if err != nil {
		return indices, fmt.Errorf("failed to load %s: %w", m.RepositoryConfig, err)
	}

	for _, re := range rf.Repositories {
		lname := re.Name
		idxFile := filepath.Join(m.RepositoryCache, helmpath.CacheIndexFile(lname))
		index, err := repo.LoadIndexFile(idxFile)
		if err != nil {
			return indices, err
		}

		// TODO: use constructor
		cr := &repo.ChartRepository{
			Config:    re,
			IndexFile: index,
		}
		indices[lname] = cr
	}
	return indices, nil
}

// writeLock writes a lockfile to disk
func writeLock(chartpath string, lock *chart.Lock, legacyLockfile bool) error {
	data, err := yaml.Marshal(lock)
	if err != nil {
		return err
	}
	lockfileName := "Chart.lock"
	if legacyLockfile {
		lockfileName = "requirements.lock"
	}
	dest := filepath.Join(chartpath, lockfileName)

	info, err := os.Lstat(dest)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error getting info for %q: %w", dest, err)
	} else if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(dest)
			if err != nil {
				return fmt.Errorf("error reading symlink for %q: %w", dest, err)
			}
			return fmt.Errorf("the %s file is a symlink to %q", lockfileName, link)
		}
	}

	return os.WriteFile(dest, data, 0o644)
}

// archive a dep chart from local directory and save it into destPath
func tarFromLocalDir(chartpath, name, repo, version, destPath string, sourceDateEpoch *time.Time) (string, error) {
	if !strings.HasPrefix(repo, "file://") {
		return "", fmt.Errorf("wrong format: chart %s repository %s", name, repo)
	}

	origPath, err := resolver.GetLocalPath(repo, chartpath)
	if err != nil {
		return "", err
	}

	ch, err := loader.LoadDir(origPath)
	if err != nil {
		return "", err
	}

	if sourceDateEpoch != nil {
		ch.StampModTimes(*sourceDateEpoch)
	}

	constraint, err := semver.NewConstraint(version)
	if err != nil {
		return "", fmt.Errorf("dependency %s has an invalid version/constraint format: %w", name, err)
	}

	v, err := semver.NewVersion(ch.Metadata.Version)
	if err != nil {
		return "", err
	}

	if constraint.Check(v) {
		_, err = chartutil.Save(ch, destPath)
		return ch.Metadata.Version, err
	}

	return "", fmt.Errorf("can't get a valid version for dependency %s", name)
}

// The prefix to use for cache keys created by the manager for repo names
const managerKeyPrefix = "helm-manager-"

// key is used to turn a name, such as a repository url, into a filesystem
// safe name that is unique for querying. To accomplish this a unique hash of
// the string is used.
func key(name string) (string, error) {
	in := strings.NewReader(name)
	hash := crypto.SHA256.New()
	if _, err := io.Copy(hash, in); err != nil {
		return "", nil
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
