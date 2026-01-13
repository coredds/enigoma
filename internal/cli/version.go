// Package cli provides the version command for enigoma.
//
// Copyright (c) 2025 David Duarte
// Licensed under the MIT License
package cli

import (
	"fmt"

	"github.com/coredds/enigoma"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of enigoma",
	Long: `Display the current version of enigoma.

Examples:
  enigoma version
  enigoma --version`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("enigoma version %s\n", enigoma.GetVersion())
	},
}
