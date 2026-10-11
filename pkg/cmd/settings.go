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

package cmd

import (
	"io"

	"github.com/spf13/cobra"

	"helm.sh/helm/v4/pkg/cli"
	"helm.sh/helm/v4/pkg/cmd/require"
)

var settingsHelp = `
Settings reports the effective value of every Helm CLI setting key and where
that value came from.

Each value is attributed to one of these sources, in precedence order:

- a command-line flag
- an environment variable
- a path variable (HELM_*_HOME takes precedence over the XDG_*_HOME variables)
- the current kubeconfig context (namespace only)
- the built-in default

The report lists every value observed for a key, marks the effective one and
explains why the other values were shadowed. It also summarizes:

- keys without any explicit source (built-in default only)
- keys whose multiple sources disagree on the value
- values whose format or semantics are invalid
- sources that could not be read

Only the effective values are used by Helm; the report never changes them.
Environment and path variable sources are flagged as [external] to make
environment noise easy to spot. Credential values are redacted.

The report is human readable. The machine readable 'helm env' output is not
affected. Pass a key name to inspect a single key, for example:

  helm settings HELM_NAMESPACE

Invalid values only fail a command when --strict-settings is set; otherwise
Helm keeps its usual fallback behavior.
`

func newSettingsCmd(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "settings [KEY]",
		Short: "report the effective CLI settings and where their values came from",
		Long:  settingsHelp,
		Args:  require.MaximumNArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return settings.Keys(), cobra.ShellCompDirectiveNoFileComp
			}
			return noMoreArgsComp()
		},
		RunE: func(_ *cobra.Command, args []string) error {
			key := ""
			if len(args) == 1 {
				key = args[0]
			}
			return cli.WriteReport(out, settings.Provenance(), key)
		},
	}
	return cmd
}
