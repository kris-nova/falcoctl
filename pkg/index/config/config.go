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

package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/falcosecurity/falcoctl/internal/config"
)

// Entry contains information about one of the index that were cached locally.
type Entry struct {
	AddedTimestamp   string `yaml:"added_timestamp"`
	Name             string `yaml:"name"`
	UpdatedTimestamp string `yaml:"updated_timestamp"`
	URL              string `yaml:"url"`
	Backend          string `yaml:"backend"`
	Token            string `yaml:"token"`
	// TODO: add support for HTTP and other backend configs.
	// HTTP             http.BackendConfig `yaml:"http"`
}

// TODO: add support for HTTP backend config fields.
// type BackendConfig struct {
//    CaFile                string `yaml:"caFile"`
//    CertFile              string `yaml:"certFile"`
//    InsecureSkipTLSVerify string `yaml:"insecure_skip_tls_verify"`
//    KeyFile               string `yaml:"keyFile"`
//    PassCredentialsAll    string `yaml:"pass_credentials_all"`
//    Password              string `yaml:"password"`
//    Username              string `yaml:"username"`
// }

// Config aggregates the info about ConfigEntries.
type Config struct {
	Configs []*Entry `yaml:"configs"`
}

// New loads an index config from a file.
func New(path string) (*Config, error) {
	var conf Config
	file, err := os.ReadFile(filepath.Clean(path))
	if os.IsNotExist(err) {
		return &conf, nil
	} else if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(file, &conf)
	if err != nil {
		return nil, err
	}

	return &conf, nil
}

// EntryFromIndex creates a Entry from a config.Index.
func EntryFromIndex(idx *config.Index) *Entry {
	return &Entry{
		Name:    idx.Name,
		URL:     idx.URL,
		Backend: idx.Backend,
	}
}

// Add adds a new config to Config.
func (c *Config) Add(entry *Entry) {
	c.Configs = append(c.Configs, entry)
}

// Upsert replaces the entry if already exists otherwise just appends it.
func (c *Config) Upsert(entry *Entry) {
	for i, e := range c.Configs {
		if entry.Name == e.Name {
			c.Configs[i] = entry
			return
		}
	}
	c.Add(entry)
}

// Remove removes a config by name from an Config.
func (c *Config) Remove(name string) {
	for k, conf := range c.Configs {
		if conf.Name == name {
			c.Configs = append(c.Configs[:k], c.Configs[k+1:]...)
			break
		}
	}
}

// Get returns a pointer to an entry in a Config.
func (c *Config) Get(name string) *Entry {
	for k, conf := range c.Configs {
		if conf.Name == name {
			return c.Configs[k]
		}
	}

	return nil
}

// Write writes a Config to disk.
func (c *Config) Write(path string) error {
	// Get dir path.
	dir, _ := filepath.Split(path)
	// Create directory if it does not exist.
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		err = os.MkdirAll(dir, DefaultDirPermissions) // #nosec G301 //we want 755 permissions
		if err != nil {
			return err
		}
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	err = os.WriteFile(path, data, DefaultFilePermissions)
	if err != nil {
		return err
	}

	return nil
}
