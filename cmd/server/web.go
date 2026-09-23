// SPDX-License-Identifier: EUPL-1.2

package main

import (
	app "github.com/digimaks/api-wallet"
	"github.com/digimaks/api-wallet/routes"

	"azugo.io/core/server"
	"github.com/spf13/cobra"
)

// webCmd represents the web command.
var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Start web server",
	Long: `Web server is the only thing you need to run,
and it takes care of all the other things for you`,
	RunE: runWeb,
}

func runWeb(cmd *cobra.Command, _ []string) error {
	a, err := app.New(cmd, Version)
	if err != nil {
		return err
	}

	if err = routes.Init(a); err != nil {
		return err
	}

	server.Run(a)

	return nil
}

func init() {
	initRootCmd()
	RootCmd.AddCommand(webCmd)
}
