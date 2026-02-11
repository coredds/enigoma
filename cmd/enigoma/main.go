// Package main provides the enigoma command-line interface.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package main

import (
	"os"

	"github.com/coredds/enigoma/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
