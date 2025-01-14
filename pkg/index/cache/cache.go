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

package cache

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/consts"
	indexConf "github.com/falcosecurity/falcoctl/pkg/index/config"
	"github.com/falcosecurity/falcoctl/pkg/index/fetch"
	"github.com/falcosecurity/falcoctl/pkg/index/index"
)

// Cache manages the index files.
type Cache struct {
	*index.MergedIndexes
	fetcher          *fetch.Fetcher
	localIndexes     *indexConf.Config
	localIndexesFile string
	indexesDir       string
	// Track the new indexes that need to be saved locally when writing the cache to file.
	fetchedIndexes []*index.Index
	// Track the indexes that have been removed, needed when writing the cache to file.
	removedIndexes []string
}

// New creates a new cache object. For each entry in the indexes.yaml file it loads the respective index file
// found on the disk or fetches it if not found. If there is an entry in the indexes.yaml file but its index file does not exist on the disk
// then it will error.
func New(ctx context.Context, indexFile, indexesDir string) (*Cache, error) {
	var err error
	var idx *index.Index

	indexConfig, err := indexConf.New(indexFile)
	if err != nil {
		return nil, fmt.Errorf("an error occurred while loading index file %q from disk: %w", indexFile, err)
	}

	c := &Cache{
		fetcher:          fetch.NewFetcher(),
		localIndexes:     indexConfig,
		localIndexesFile: indexFile,
		indexesDir:       indexesDir,
		MergedIndexes:    index.NewMergedIndexes(),
	}

	// Load existing indexes in memory and merge them.
	for _, cfg := range c.localIndexes.Configs {
		// If the index is in the local persistent cache we just load it.
		if idx, err = c.loadIndex(cfg.Name); err != nil && errors.Is(err, fs.ErrNotExist) {
			// If the index is not found in the local persistent cache we fetch it from the url.
			ts := time.Now().Format(consts.TimeFormat)
			if idx, err = c.fetcher.Fetch(ctx, cfg); err != nil {
				return nil, fmt.Errorf("unable to fetch index %q with URL %q: %w", cfg.Name, cfg.URL, err)
			}
			// If correctly fetched, we need to update the metadata of the config entry.
			cfg.UpdatedTimestamp = ts
			if cfg.AddedTimestamp == "" {
				cfg.AddedTimestamp = ts
			}
			c.localIndexes.Upsert(cfg)
			c.fetchedIndexes = append(c.fetchedIndexes, idx)
		} else if err != nil {
			return nil, fmt.Errorf("an error occurred while loading cache from disk: %w", err)
		}
		// After a successful load/fetch we merge it.
		c.Merge(idx)
	}

	return c, nil
}

// NewFromConfig creates a new cache object from a set of indexes. The new cache fetches the indexes only if they do not
// exist in the filesystem. The local indexes info is ignored, it takes into account the indexes passed as arguments.
func NewFromConfig(ctx context.Context, indexFile, indexesDir string, indexes []config.Index) (*Cache, error) {
	var err error
	var idx *index.Index
	indexConfig := &indexConf.Config{}

	c := &Cache{
		fetcher:          fetch.NewFetcher(),
		localIndexes:     indexConfig,
		localIndexesFile: indexFile,
		indexesDir:       indexesDir,
		MergedIndexes:    index.NewMergedIndexes(),
	}

	for i := range indexes {
		cfg := &indexes[i]
		// If the index is in the local persistent cache we just load it.
		ts := time.Now().Format(consts.TimeFormat)
		if idx, err = c.loadIndex(cfg.Name); err != nil && errors.Is(err, fs.ErrNotExist) {
			// If the index is not found in the local persistent cache we fetch it from the url.
			if idx, err = c.fetcher.Fetch(ctx, indexConf.EntryFromIndex(cfg)); err != nil {
				return nil, fmt.Errorf("unable to fetch index %q with URL %q: %w", cfg.Name, cfg.URL, err)
			}
			c.fetchedIndexes = append(c.fetchedIndexes, idx)
		} else if err != nil {
			return nil, fmt.Errorf("an error occurred while loading cache from disk: %w", err)
		}
		c.localIndexes.Configs = append(c.localIndexes.Configs, &indexConf.Entry{
			AddedTimestamp:   ts,
			Name:             cfg.Name,
			UpdatedTimestamp: ts,
			URL:              cfg.URL,
		})
		// After a successful load/fetch we merge it.
		c.Merge(idx)
	}

	return c, nil
}

// Add adds a new index file to the cache. If the index file already exists in the cache it
// does nothing. On the other hand, it fetches the index file using the provided URL and adds
// it to the in memory cache. It does not write it to the filesystem. It is idempotent.
func (c *Cache) Add(ctx context.Context, name, backend, url, token string) error {
	var remoteIndex *index.Index
	var err error

	entry := c.localIndexes.Get(name)

	// If it exists already, return.
	if entry != nil {
		return nil
	}

	entry = &indexConf.Entry{
		Name:    name,
		URL:     url,
		Backend: backend,
		Token:   token,
	}

	// If the index is not locally cached we fetch it using the provided url.
	if remoteIndex, err = c.fetcher.Fetch(ctx, entry); err != nil {
		return fmt.Errorf("unable to fetch index %q with URL %q: %w", name, url, err)
	}

	// Keep track of the newly created index file.
	ts := time.Now().Format(consts.TimeFormat)
	entry = &indexConf.Entry{
		Name:             remoteIndex.Name,
		AddedTimestamp:   ts,
		UpdatedTimestamp: ts,
		URL:              url,
		Backend:          backend,
		Token:            token,
	}
	c.localIndexes.Add(entry)

	// Save it for later write operation.
	c.fetchedIndexes = append(c.fetchedIndexes, remoteIndex)

	c.Merge(remoteIndex)

	// If the index has been removed before we make sure to delete it from the removedIndexes array.
	for i, idxName := range c.removedIndexes {
		if idxName == name {
			c.removedIndexes = append(c.removedIndexes[:i], c.removedIndexes[i+1:]...)
		}
	}

	return nil
}

// Remove removes an index file from the cache if it exists.
func (c *Cache) Remove(name string) error {
	var idx *index.Index
	var err error
	newMergedIndex := index.NewMergedIndexes()
	// Check if the index is in the local cache.
	entry := c.localIndexes.Get(name)
	if entry == nil {
		return nil
	}

	// Create a new merged indexes without the one we are removing.
	for _, cfg := range c.localIndexes.Configs {
		if cfg.Name != name {
			if idx, err = c.loadIndex(cfg.Name); err != nil && errors.Is(err, fs.ErrNotExist) {
				idx = findIndexInSlice(c.fetchedIndexes, cfg.Name)
				if idx == nil {
					return fmt.Errorf("index %q not found in the local persisten storage neither in the fetched indexes", cfg.Name)
				}
			} else if err != nil {
				return err
			}
			newMergedIndex.Merge(idx)
		}
	}

	c.MergedIndexes = newMergedIndex
	c.removedIndexes = append(c.removedIndexes, name)

	// Remove the index from the indexes list.
	c.localIndexes.Remove(name)

	// Remove the index from the fetchedIndexes if present.
	for i, idx := range c.fetchedIndexes {
		if idx.Name == name {
			c.fetchedIndexes = append(c.fetchedIndexes[:i], c.fetchedIndexes[i+1:]...)
		}
	}

	return nil
}

// Update updates an index entry by fetching the new content from the configured URL for the
// given index. The new content is kept in memory, it does not overwrite the existing index file
// on the disk.
func (c *Cache) Update(ctx context.Context, name string) error {
	var idx *index.Index
	var err error
	newMergedIndex := index.NewMergedIndexes()
	// Check if the entry exists.
	entry := c.localIndexes.Get(name)
	if entry == nil {
		return fmt.Errorf("unable to update index %s: not found in the cache, please make sure to add it before updating", name)
	}

	ts := time.Now().Format(consts.TimeFormat)
	// Fetch the index from the remote url.
	updatedIndex, err := c.fetcher.Fetch(ctx, entry)
	if err != nil {
		return fmt.Errorf("unable to fetch index %q with URL %q: %w", name, entry.URL, err)
	}

	// Update the existing index entry by setting the new timestamp.
	entry.UpdatedTimestamp = ts
	c.localIndexes.Upsert(entry)

	// Track the new fetched index for writing purposes.
	c.fetchedIndexes = append(c.fetchedIndexes, updatedIndex)

	// Create a new merged indexes without the one we are removing.
	for _, cfg := range c.localIndexes.Configs {
		if cfg.Name != name {
			if idx, err = c.loadIndex(cfg.Name); err != nil && errors.Is(err, fs.ErrNotExist) {
				idx = findIndexInSlice(c.fetchedIndexes, cfg.Name)
				if idx == nil {
					return fmt.Errorf("index %q not found in the local persisten storage neither in the fetched indexes", cfg.Name)
				}
			} else if err != nil {
				return err
			}
			newMergedIndex.Merge(idx)
		} else {
			newMergedIndex.Merge(updatedIndex)
		}
	}

	return nil
}

// Write dumps the in-memory cache to disk. Based on the cache operations it does different things.
// Add: a new entry is added to the config.IndexesFile and the fetched index file is saved under the
// config.IndexesDir.
// Remove: the removed entry is wiped out from the config.IndexesFile and the related index file is deleted.
// Update: the entry in the config.IndexesFile for the updated index is updated. The related index file is
// replaced by the new content fetched by the update operation.
// Returns the indexConf.Config written to the config.IndexesFile.
func (c *Cache) Write() (*indexConf.Config, error) {
	for _, idx := range c.fetchedIndexes {
		indexFileName := fmt.Sprintf("%s%s", idx.Name, ".yaml")
		indexPath := filepath.Join(c.indexesDir, indexFileName)

		// Save the new index.
		if err := idx.Write(indexPath); err != nil {
			return nil, fmt.Errorf("an error occurred while writing index %q to file %q: %w", idx.Name, indexPath, err)
		}
	}

	for _, name := range c.removedIndexes {
		indexFileName := fmt.Sprintf("%s%s", name, ".yaml")
		indexPath := filepath.Join(c.indexesDir, indexFileName)
		if err := os.Remove(indexPath); err != nil {
			return nil, fmt.Errorf("an error occurred while removeing index %q from %q: %w", name, indexPath, err)
		}
		c.localIndexes.Remove(name)
	}

	if err := c.localIndexes.Write(c.localIndexesFile); err != nil {
		return nil, fmt.Errorf("an error occurred while writing indexes file to path %q: %w", c.localIndexesFile, err)
	}

	return c.localIndexes, nil
}

func (c *Cache) loadIndex(name string) (*index.Index, error) {
	indexFileName := fmt.Sprintf("%s%s", name, ".yaml")

	idx := index.New(name)
	indexPath := filepath.Join(c.indexesDir, indexFileName)
	err := idx.Read(indexPath)
	if err != nil {
		return nil, fmt.Errorf("an error occurred while loading index %q from file %q: %w", name, indexPath, err)
	}

	return idx, nil
}

func findIndexInSlice(indexes []*index.Index, name string) *index.Index {
	for _, idx := range indexes {
		if idx.Name == name {
			return idx
		}
	}

	return nil
}
