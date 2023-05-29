// Copyright 2020-2023 Buf Technologies, Inc.
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

package bufinit

import (
	"fmt"
	"sort"

	"github.com/bufbuild/buf/private/pkg/normalpath"
)

type calculation struct {
	// A map from file path to the fileInfo that represents this file.
	FilePathToFileInfo map[string]*fileInfo
	// A map from -I directories based on detected imports, to the imports contained within them.
	// Based off of the reverse trie lookup - if a file is detected to be potentially within
	// a given directory and it is imported, this is added as an import dir path, while the
	// import is added to the values for import dir path.
	//
	// Example: if "a/b/c.proto" is a file in FilePathToFileInfo, and some file imports "c.proto",
	// then this map will contain "a/b" -> "c.proto".
	//
	// Note that this might add directories that are do not actually make sense as import directories/
	// For example, in bufbuild/buf, we have imports in tests like "2.proto", but there are a lot
	// of "2.protos" in bufbuild/buf, so if we import "2.proto" anywhere, every directory that
	// contains a "2.proto" will be added as an importDirPath.
	//
	// The idea is that if you were to include all these directories, you would have a superset
	// of the directories you need to compile everything.
	//
	// normalpath.Join(importDirPath, importPath) should always be a key in FilePathToFileInfo.
	ImportDirPathToImportPaths map[string]map[string]struct{}
	//ImportPathToImportDirPaths is the inverse of ImportDirPathToImportPaths, that is for a given
	// "c.proto", it will tell you all directories with a "c.proto.
	ImportPathToImportDirPaths map[string]map[string]struct{}
	// A map from an import that is not detected in the fileInfos, to the file paths that contain
	// this missing import.
	//
	// Example: "a/b/c.proto" imports "gogo.proto", but "gogo.proto" is not detected to be a
	// fileInfo that we have, regardless of how many directories we have stripped (so we don't
	// have ".*/gogo.proto").
	MissingImportPathToFilePaths map[string]map[string]struct{}
}

func newCalculation() *calculation {
	return &calculation{
		FilePathToFileInfo:           make(map[string]*fileInfo),
		ImportDirPathToImportPaths:   make(map[string]map[string]struct{}),
		ImportPathToImportDirPaths:   make(map[string]map[string]struct{}),
		MissingImportPathToFilePaths: make(map[string]map[string]struct{}),
	}
}

func (c *calculation) AllImportDirPaths() []string {
	importDirPaths := make([]string, 0, len(c.ImportDirPathToImportPaths))
	for importDirPath := range c.ImportDirPathToImportPaths {
		importDirPaths = append(importDirPaths, importDirPath)
	}
	sort.Strings(importDirPaths)
	return importDirPaths
}

func (c *calculation) addFileInfo(fileInfo *fileInfo) error {
	if _, ok := c.FilePathToFileInfo[fileInfo.Path]; ok {
		// we don't expect this from our production of fileInfos, this is a system error
		return fmt.Errorf("calculation: duplicate filePath: %q", fileInfo.Path)
	}
	c.FilePathToFileInfo[fileInfo.Path] = fileInfo
	return nil
}

func (c *calculation) addImportDirPathAndImportPath(importDirPath string, importPath string) error {
	importPathMap, ok := c.ImportDirPathToImportPaths[importDirPath]
	if !ok {
		importPathMap = make(map[string]struct{})
		c.ImportDirPathToImportPaths[importDirPath] = importPathMap
	}
	importPathMap[importPath] = struct{}{}
	importDirPathMap, ok := c.ImportPathToImportDirPaths[importPath]
	if !ok {
		importDirPathMap = make(map[string]struct{})
		c.ImportPathToImportDirPaths[importPath] = importDirPathMap
	}
	importDirPathMap[importDirPath] = struct{}{}
	return nil
}

func (c *calculation) addMissingImportPathAndFilePath(missingImportPath string, filePath string) error {
	filePathMap, ok := c.MissingImportPathToFilePaths[missingImportPath]
	if !ok {
		filePathMap = make(map[string]struct{})
		c.MissingImportPathToFilePaths[missingImportPath] = filePathMap
	}
	filePathMap[filePath] = struct{}{}
	return nil
}

// TODO: could validate that every filePath in MissingImportPathToFilePaths is in FilePathToFileInfo.
func (c *calculation) postValidate() error {
	for importDirPath, importPathMap := range c.ImportDirPathToImportPaths {
		for importPath := range importPathMap {
			joinedPath := normalpath.Join(importDirPath, importPath)
			if _, ok := c.FilePathToFileInfo[joinedPath]; !ok {
				return fmt.Errorf("calculation: had importDirPath %q and importPath %q but no corresponding filePath", importDirPath, importPath)
			}
		}
	}
	return nil
}
