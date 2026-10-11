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

/*
Package cli describes the operating environment for the Helm CLI.

Helm's environment encapsulates all of the service dependencies Helm has.
These dependencies are expressed as interfaces so that alternate implementations
(mocks, etc.) can be easily generated.
*/
package cli

import (
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"

	"helm.sh/helm/v4/internal/version"
	"helm.sh/helm/v4/pkg/helmpath"
	"helm.sh/helm/v4/pkg/kubeenv"
)

// defaultMaxHistory sets the maximum number of releases to 0: unlimited
const defaultMaxHistory = 10

// defaultBurstLimit sets the default client-side throttling limit
const defaultBurstLimit = 100

// defaultQPS sets the default QPS value to 0 to use library defaults unless specified
const defaultQPS = float32(0)

// EnvSettings describes all of the environment settings.
type EnvSettings struct {
	namespace string
	config    *genericclioptions.ConfigFlags

	// KubeConfig is the path to the kubeconfig file
	KubeConfig string
	// KubeContext is the name of the kubeconfig context.
	KubeContext string
	// Bearer KubeToken used for authentication
	KubeToken string
	// Username to impersonate for the operation
	KubeAsUser string
	// Groups to impersonate for the operation, multiple groups parsed from a comma delimited list
	KubeAsGroups []string
	// Kubernetes API Server Endpoint for authentication
	KubeAPIServer string
	// Custom certificate authority file.
	KubeCaFile string
	// KubeInsecureSkipTLSVerify indicates if server's certificate will not be checked for validity.
	// This makes the HTTPS connections insecure
	KubeInsecureSkipTLSVerify bool
	// KubeTLSServerName overrides the name to use for server certificate validation.
	// If it is not provided, the hostname used to contact the server is used
	KubeTLSServerName string
	// Debug indicates whether or not Helm is running in Debug mode.
	Debug bool
	// RegistryConfig is the path to the registry config file.
	RegistryConfig string
	// RepositoryConfig is the path to the repositories file.
	RepositoryConfig string
	// RepositoryCache is the path to the repository cache directory.
	RepositoryCache string
	// PluginsDirectory is the path to the plugins directory.
	PluginsDirectory string
	// MaxHistory is the max release history maintained.
	MaxHistory int
	// BurstLimit is the default client-side throttling limit.
	BurstLimit int
	// QPS is queries per second which may be used to avoid throttling.
	QPS float32
	// ColorMode controls colorized output (never, auto, always)
	ColorMode string
	// ContentCache is the location where cached charts are stored
	ContentCache string
	// StrictSettings fails instead of silently falling back to the default
	// when a CLI setting has an invalid value.
	StrictSettings bool

	// flags is the flag set the settings were bound to through AddFlags. It is
	// used after parsing to determine which values came from command-line flags.
	flags *pflag.FlagSet
	// prov records every source observed while resolving the setting values.
	prov *provenance
}

func New() *EnvSettings {
	prov := newProvenance()

	// Resolve the path-derived defaults once, through the same path helpers
	// that the commands use, so that the provenance report can point at the
	// path variable (HELM_*_HOME or XDG_*_HOME) that shaped each default.
	pluginsPath, pluginsOrigin := helmpath.DataPathOrigin("plugins")
	registryPath, registryOrigin := helmpath.ConfigPathOrigin("registry/config.json")
	repositoryPath, repositoryOrigin := helmpath.ConfigPathOrigin("repositories.yaml")
	repoCachePath, repoCacheOrigin := helmpath.CachePathOrigin("repository")
	contentCachePath, contentCacheOrigin := helmpath.CachePathOrigin("content")
	prov.setPathDefault("HELM_PLUGINS", pluginsOrigin)
	prov.setPathDefault("HELM_REGISTRY_CONFIG", registryOrigin)
	prov.setPathDefault("HELM_REPOSITORY_CONFIG", repositoryOrigin)
	prov.setPathDefault("HELM_REPOSITORY_CACHE", repoCacheOrigin)
	prov.setPathDefault("HELM_CONTENT_CACHE", contentCacheOrigin)

	env := &EnvSettings{
		namespace:                 prov.envString("HELM_NAMESPACE", "HELM_NAMESPACE"),
		MaxHistory:                prov.envInt("HELM_MAX_HISTORY", "HELM_MAX_HISTORY", defaultMaxHistory),
		KubeConfig:                prov.envString("KUBECONFIG", "KUBECONFIG"),
		KubeContext:               prov.envString("HELM_KUBECONTEXT", "HELM_KUBECONTEXT"),
		KubeToken:                 prov.envString("HELM_KUBETOKEN", "HELM_KUBETOKEN"),
		KubeAsUser:                prov.envString("HELM_KUBEASUSER", "HELM_KUBEASUSER"),
		KubeAsGroups:              prov.envCSV("HELM_KUBEASGROUPS", "HELM_KUBEASGROUPS"),
		KubeAPIServer:             prov.envString("HELM_KUBEAPISERVER", "HELM_KUBEAPISERVER"),
		KubeCaFile:                prov.envString("HELM_KUBECAFILE", "HELM_KUBECAFILE"),
		KubeTLSServerName:         prov.envString("HELM_KUBETLS_SERVER_NAME", "HELM_KUBETLS_SERVER_NAME"),
		KubeInsecureSkipTLSVerify: prov.envBool("HELM_KUBEINSECURE_SKIP_TLS_VERIFY", "HELM_KUBEINSECURE_SKIP_TLS_VERIFY", false),
		PluginsDirectory:          prov.envPathString("HELM_PLUGINS", "HELM_PLUGINS", pluginsPath),
		RegistryConfig:            prov.envPathString("HELM_REGISTRY_CONFIG", "HELM_REGISTRY_CONFIG", registryPath),
		RepositoryConfig:          prov.envPathString("HELM_REPOSITORY_CONFIG", "HELM_REPOSITORY_CONFIG", repositoryPath),
		RepositoryCache:           prov.envPathString("HELM_REPOSITORY_CACHE", "HELM_REPOSITORY_CACHE", repoCachePath),
		ContentCache:              prov.envPathString("HELM_CONTENT_CACHE", "HELM_CONTENT_CACHE", contentCachePath),
		BurstLimit:                prov.envInt("HELM_BURST_LIMIT", "HELM_BURST_LIMIT", defaultBurstLimit),
		QPS:                       prov.envFloat("HELM_QPS", "HELM_QPS", defaultQPS),
		ColorMode:                 prov.envColor(),
		Debug:                     prov.envBool("HELM_DEBUG", "HELM_DEBUG", false),
		prov:                      prov,
	}

	// bind to kubernetes config flags
	config := &genericclioptions.ConfigFlags{
		Namespace:        &env.namespace,
		Context:          &env.KubeContext,
		BearerToken:      &env.KubeToken,
		APIServer:        &env.KubeAPIServer,
		CAFile:           &env.KubeCaFile,
		KubeConfig:       &env.KubeConfig,
		Impersonate:      &env.KubeAsUser,
		Insecure:         &env.KubeInsecureSkipTLSVerify,
		TLSServerName:    &env.KubeTLSServerName,
		ImpersonateGroup: &env.KubeAsGroups,
		WrapConfigFn: func(config *rest.Config) *rest.Config {
			config.Burst = env.BurstLimit
			config.QPS = env.QPS
			config.Wrap(func(rt http.RoundTripper) http.RoundTripper {
				return &kubeenv.RetryingRoundTripper{Wrapped: rt}
			})
			config.UserAgent = version.GetUserAgent()
			return config
		},
	}
	if env.BurstLimit != defaultBurstLimit {
		config = config.WithDiscoveryBurst(env.BurstLimit)
	}
	env.config = config

	return env
}

// AddFlags binds flags to the given flagset.
func (s *EnvSettings) AddFlags(fs *pflag.FlagSet) {
	s.flags = fs
	fs.StringVarP(&s.namespace, "namespace", "n", s.namespace, "namespace scope for this request")
	fs.StringVar(&s.KubeConfig, "kubeconfig", "", "path to the kubeconfig file")
	fs.StringVar(&s.KubeContext, "kube-context", s.KubeContext, "name of the kubeconfig context to use")
	fs.StringVar(&s.KubeToken, "kube-token", s.KubeToken, "bearer token used for authentication")
	fs.StringVar(&s.KubeAsUser, "kube-as-user", s.KubeAsUser, "username to impersonate for the operation")
	fs.StringArrayVar(&s.KubeAsGroups, "kube-as-group", s.KubeAsGroups, "group to impersonate for the operation, this flag can be repeated to specify multiple groups.")
	fs.StringVar(&s.KubeAPIServer, "kube-apiserver", s.KubeAPIServer, "the address and the port for the Kubernetes API server")
	fs.StringVar(&s.KubeCaFile, "kube-ca-file", s.KubeCaFile, "the certificate authority file for the Kubernetes API server connection")
	fs.StringVar(&s.KubeTLSServerName, "kube-tls-server-name", s.KubeTLSServerName, "server name to use for Kubernetes API server certificate validation. If it is not provided, the hostname used to contact the server is used")
	fs.BoolVar(&s.KubeInsecureSkipTLSVerify, "kube-insecure-skip-tls-verify", s.KubeInsecureSkipTLSVerify, "if true, the Kubernetes API server's certificate will not be checked for validity. This will make your HTTPS connections insecure")
	fs.BoolVar(&s.Debug, "debug", s.Debug, "enable verbose output")
	fs.StringVar(&s.RegistryConfig, "registry-config", s.RegistryConfig, "path to the registry config file")
	fs.StringVar(&s.RepositoryConfig, "repository-config", s.RepositoryConfig, "path to the file containing repository names and URLs")
	fs.StringVar(&s.RepositoryCache, "repository-cache", s.RepositoryCache, "path to the directory containing cached repository indexes")
	fs.StringVar(&s.ContentCache, "content-cache", s.ContentCache, "path to the directory containing cached content (e.g. charts)")
	fs.IntVar(&s.BurstLimit, "burst-limit", s.BurstLimit, "client-side default throttling limit")
	fs.Float32Var(&s.QPS, "qps", s.QPS, "queries per second used when communicating with the Kubernetes API, not including bursting")
	fs.StringVar(&s.ColorMode, "color", s.ColorMode, "use colored output (never, auto, always)")
	fs.StringVar(&s.ColorMode, "colour", s.ColorMode, "use colored output (never, auto, always)")
	fs.BoolVar(&s.StrictSettings, "strict-settings", false, "fail when a CLI setting has an invalid value instead of silently falling back to its default")
}

func envBoolOr(name string, def bool) bool {
	if name == "" {
		return def
	}
	envVal, ok := os.LookupEnv(name)
	if !ok || envVal == "" {
		return def
	}
	ret, err := strconv.ParseBool(envVal)
	if err != nil {
		return def
	}
	return ret
}

func (s *EnvSettings) EnvVars() map[string]string {
	envvars := map[string]string{
		"HELM_BIN":               os.Args[0],
		"HELM_CACHE_HOME":        helmpath.CachePath(""),
		"HELM_CONFIG_HOME":       helmpath.ConfigPath(""),
		"HELM_DATA_HOME":         helmpath.DataPath(""),
		"HELM_DEBUG":             strconv.FormatBool(s.Debug),
		"HELM_PLUGINS":           s.PluginsDirectory,
		"HELM_REGISTRY_CONFIG":   s.RegistryConfig,
		"HELM_REPOSITORY_CACHE":  s.RepositoryCache,
		"HELM_CONTENT_CACHE":     s.ContentCache,
		"HELM_REPOSITORY_CONFIG": s.RepositoryConfig,
		"HELM_NAMESPACE":         s.Namespace(),
		"HELM_MAX_HISTORY":       strconv.Itoa(s.MaxHistory),
		"HELM_BURST_LIMIT":       strconv.Itoa(s.BurstLimit),
		"HELM_QPS":               strconv.FormatFloat(float64(s.QPS), 'f', 2, 32),

		// broken, these are populated from helm flags and not kubeconfig.
		"HELM_KUBECONTEXT":                  s.KubeContext,
		"HELM_KUBETOKEN":                    s.KubeToken,
		"HELM_KUBEASUSER":                   s.KubeAsUser,
		"HELM_KUBEASGROUPS":                 strings.Join(s.KubeAsGroups, ","),
		"HELM_KUBEAPISERVER":                s.KubeAPIServer,
		"HELM_KUBECAFILE":                   s.KubeCaFile,
		"HELM_KUBEINSECURE_SKIP_TLS_VERIFY": strconv.FormatBool(s.KubeInsecureSkipTLSVerify),
		"HELM_KUBETLS_SERVER_NAME":          s.KubeTLSServerName,
	}
	if s.KubeConfig != "" {
		envvars["KUBECONFIG"] = s.KubeConfig
	}
	return envvars
}

// Namespace gets the namespace from the configuration
func (s *EnvSettings) Namespace() string {
	if s.config != nil {
		if ns, _, err := s.config.ToRawKubeConfigLoader().Namespace(); err == nil {
			return ns
		}
	}
	if s.namespace != "" {
		return s.namespace
	}
	return "default"
}

// SetNamespace sets the namespace in the configuration
func (s *EnvSettings) SetNamespace(namespace string) {
	s.namespace = namespace
}

// RESTClientGetter gets the kubeconfig from EnvSettings
func (s *EnvSettings) RESTClientGetter() genericclioptions.RESTClientGetter {
	return s.config
}

// ShouldDisableColor returns true if color output should be disabled
func (s *EnvSettings) ShouldDisableColor() bool {
	return s.ColorMode == "never"
}
