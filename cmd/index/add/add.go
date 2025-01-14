// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package add

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/pkg/index/cache"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

// IndexAddOptions contains the options for the index add command.
type IndexAddOptions struct {
	*options.Common
}

// NewIndexAddCmd returns the index add command.
func NewIndexAddCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	o := IndexAddOptions{
		Common: opt,
	}

	cmd := &cobra.Command{
		Use:                   "add [NAME] [URL] [BACKEND] [TOKEN] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Add an index to the local falcoctl configuration",
		Long:                  "Add an index to the local falcoctl configuration. Indexes are used to perform search operations for artifacts\nIf you need authentication for using private index. You have to use token ( base64 encode \"HeaderName:Token\" )",
		Args:                  cobra.RangeArgs(2, 4),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunIndexAdd(ctx, args)
		},
	}

	return cmd
}

// RunIndexAdd implements the index add command.
func (o *IndexAddOptions) RunIndexAdd(ctx context.Context, args []string) error {
	var err error
	logger := o.Printer.Logger

	name := args[0]
	url := args[1]
	backend := ""
	token := ""
	if len(args) == 3 {
		backend = args[2]
	} else if len(args) == 4 {
		backend = args[2]
		token = args[3]
	}

	logger.Debug("Creating in-memory cache using", logger.Args("indexes file", config.IndexesFile, "indexes directory", config.IndexesDir))
	indexCache, err := cache.New(ctx, config.IndexesFile, config.IndexesDir)
	if err != nil {
		return fmt.Errorf("unable to create index cache: %w", err)
	}

	logger.Info("Adding index", logger.Args("name", name, "path", url))

	if err = indexCache.Add(ctx, name, backend, url, token); err != nil {
		return fmt.Errorf("unable to add index: %w", err)
	}

	logger.Debug("Writing cache to disk")
	if _, err = indexCache.Write(); err != nil {
		return fmt.Errorf("unable to write cache to disk: %w", err)
	}

	logger.Debug("Adding new index entry to configuration", logger.Args("file", o.ConfigFile))
	if err = config.AddIndexes([]config.Index{{
		Name:    name,
		URL:     url,
		Backend: backend,
	}}, o.ConfigFile); err != nil {
		return fmt.Errorf("index entry %q: %w", name, err)
	}

	logger.Info("Index successfully added")

	return nil
}
