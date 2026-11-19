package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"go.kenn.io/msgvault/internal/oauth"
)

var addQuotaAppName string

// quotaTokenNamespace keeps a quota app's sign-in apart from the account's own
// token, which stays with the app the account is bound to.
func quotaTokenNamespace(app string) string { return "quota/" + app }

var addQuotaAppCmd = &cobra.Command{
	Use:   "add-quota-app <email>",
	Short: "Authorize a Gmail account on an extra Google project for more sync quota",
	Long: `Gmail counts its per-user quota per Google project. This signs the account
in, read-only, through another configured [oauth.apps.<name>] project. Projects
listed in [sync] quota_apps then share a sync's message downloads.`,
	Example: `  msgvault add-quota-app you@gmail.com --oauth-app quota2`,
	Args:    validateAddAccountArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		state := invocationFromCommand(cmd)
		if state == nil || state.cfg == nil || state.logger == nil {
			return errors.New("configuration is unavailable")
		}
		if addQuotaAppName == "" {
			return usageErr(cmd, errors.New("--oauth-app is required"))
		}
		cfg := state.cfg
		credentials, err := cfg.OAuth.CredentialsFor(addQuotaAppName)
		if err != nil {
			return err
		}
		mgr, err := oauth.NewManagerWithCredentials(cmd.Context(), credentials, cfg.TokensDir(),
			cfg.OAuth.Tokens, state.logger, oauth.ScopesGmailReadonly)
		if err != nil {
			return wrapOAuthError(fmt.Errorf("create oauth manager: %w", err), cfg)
		}
		if err := mgr.WithTokenNamespace(quotaTokenNamespace(addQuotaAppName)).Authorize(cmd.Context(), args[0]); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s authorized on quota app %q.\n", args[0], addQuotaAppName)
		return nil
	},
}

func init() {
	addQuotaAppCmd.Flags().StringVar(&addQuotaAppName, "oauth-app", "", "Named OAuth app from config to authorize")
	rootCmd.AddCommand(addQuotaAppCmd)
}
