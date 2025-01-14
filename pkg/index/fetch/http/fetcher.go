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

package http

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/falcosecurity/falcoctl/pkg/index/config"
)

// Fetch fetches the raw index file from the given HTTP/S url.
func Fetch(ctx context.Context, conf *config.Entry) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", conf.URL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch index: %w", err)
	}

	if conf.Token != "" {
		tokenString, err := base64.StdEncoding.DecodeString(conf.Token)
		if err != nil {
			return nil, fmt.Errorf("unable to parse index token: %w", err)
		}
		indexToken := strings.Split(string(tokenString), ":")
		req.Header.Add(indexToken[0], indexToken[1])
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch index: %w", err)
	}
	defer resp.Body.Close() // #nosec G307 closing errors should not happen

	if resp.StatusCode >= http.StatusBadRequest && resp.StatusCode <= http.StatusNetworkAuthenticationRequired {
		return nil, fmt.Errorf("cannot fetch index: %s", resp.Status)
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read bytes from response body: %w", err)
	}

	return bytes, nil
}
