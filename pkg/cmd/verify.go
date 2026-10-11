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
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/cmd/require"
)

const verifyDesc = `
Verify that the given chart has a valid provenance file.

Provenance files provide cryptographic verification that a chart has not been
tampered with, and was packaged by a trusted provider.

This command can be used to verify a local chart. Several other commands provide
'--verify' flags that run the same validation. To generate a signed package, use
the 'helm package --sign' command.

Verification can additionally follow a policy that merges several keyring files
and key directories (each key keeps its source annotation), admits or rejects
signing identities and fingerprints, requires signature annotations, and
requires a minimum number of valid signatures spread across distinct sources.
Policy files are merged in the order given and command-line flags take
precedence over policy files. See '--verify-policy' and the related flags.
`

func newVerifyCmd(out io.Writer) *cobra.Command {
	client := action.NewVerify()

	cmd := &cobra.Command{
		Use:   "verify PATH",
		Short: "verify that a chart at the given path has been signed and is valid",
		Long:  verifyDesc,
		Args:  require.ExactArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				// Allow file completion when completing the argument for the path
				return nil, cobra.ShellCompDirectiveDefault
			}
			// No more completions, so disable file completion
			return noMoreArgsComp()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			client.KeyringExplicit = cmd.Flags().Changed("keyring")
			result, err := client.Run(args[0])
			if err != nil {
				return err
			}

			fmt.Fprint(out, result)

			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&client.Keyring, "keyring", defaultKeyring(), "keyring containing public keys")
	f.StringArrayVar(&client.PolicyFiles, "verify-policy", nil,
		"verification policy file to use (can be specified multiple times; merged in order)")
	f.StringArrayVar(&client.ExtraKeyrings, "extra-keyring", nil,
		"additional keyring file to merge for verification (can be specified multiple times)")
	f.StringArrayVar(&client.KeyDirs, "key-dir", nil,
		"directory of keyring files to merge for verification (can be specified multiple times)")
	f.StringArrayVar(&client.IdentityAllow, "allow-identity", nil,
		"admit only signatures by identities matching the entry (exact or glob; can be specified multiple times); overrides policy files")
	f.StringArrayVar(&client.IdentityDeny, "deny-identity", nil,
		"reject signatures by identities matching the entry (exact or glob; can be specified multiple times); overrides policy files")
	f.StringArrayVar(&client.IdentityRequiredPatterns, "require-identity-pattern", nil,
		"require the signer identity to match this regular expression (can be specified multiple times); overrides policy files")
	f.StringArrayVar(&client.FingerprintAllow, "allow-fingerprint", nil,
		"admit only signatures by these key fingerprints (full fingerprint or key-id suffix; repeatable); overrides policy files")
	f.StringArrayVar(&client.FingerprintDeny, "deny-fingerprint", nil,
		"reject signatures by these key fingerprints (full fingerprint or key-id suffix; repeatable); overrides policy files")
	f.StringArrayVar(&client.FingerprintRequiredPatterns, "require-fingerprint-pattern", nil,
		"require the signer fingerprint to match this regular expression (repeatable); overrides policy files")
	f.IntVar(&client.MinValidSignatures, "min-valid-signatures", 0,
		"minimum number of valid, admitted signatures required (default 1 when a policy is in force); overrides policy files")
	f.IntVar(&client.MinDistinctSources, "min-distinct-sources", 0,
		"minimum number of distinct key sources the valid signatures must come from; overrides policy files")
	f.StringToStringVar(&client.RequiredAnnotations, "require-annotation", nil,
		"require a signature annotation (OpenPGP notation) key=value (repeatable); overrides policy files")

	return cmd
}
