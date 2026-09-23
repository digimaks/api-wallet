// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

// Version holds the current application version.
var Version = "1.0.0-dev"

// RootCmd represents the base command when called without any subcommands.
var RootCmd *cobra.Command

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func initRootCmd() {
	if RootCmd != nil {
		return
	}

	RootCmd = &cobra.Command{
		Use:   "server",
		Short: "Server",
		Long: `By default, server will start serving using the web server with no
  arguments - which can alternatively be run by running the subcommand web.`,
		RunE: runWeb,
	}
}

func main() {
	initRootCmd()

	RootCmd.Version = Version

	if _, ok := os.LookupEnv("SERVER_URLS"); !ok {
		_ = os.Setenv("SERVER_URLS", "http://0.0.0.0:8080")
	}

	Execute()
}
