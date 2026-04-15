// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scriberoots

import (
	"embed"
)

//go:embed certdata/*
var ScribeRoots embed.FS

// GetScribeRoot retrieves the content of a specific scribe root file.
func GetScribeRoot(filename string) ([]byte, error) {
	return ScribeRoots.ReadFile(filename)
}

// GetAllScribeRoots retrieves the content of all embedded scribe root files.
func GetAllScribeRoots() (map[string][]byte, error) {
	rootFiles := make(map[string][]byte)
	prefix := "certdata"
	entries, err := ScribeRoots.ReadDir(prefix)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			content, err := ScribeRoots.ReadFile(prefix + "/" + entry.Name())
			if err != nil {
				return nil, err
			}
			rootFiles[entry.Name()] = content
		}
	}
	return rootFiles, nil
}