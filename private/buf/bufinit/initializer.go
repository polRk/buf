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
	"context"
	"encoding/json"
	"fmt"

	"github.com/bufbuild/buf/private/pkg/storage"
	"github.com/bufbuild/protocompile/ast"
	"github.com/bufbuild/protocompile/parser"
	"github.com/bufbuild/protocompile/reporter"
	"go.uber.org/zap"
)

type initializer struct {
	logger *zap.Logger
}

func newInitializer(logger *zap.Logger) *initializer {
	return &initializer{
		logger: logger,
	}
}

func (i *initializer) Initialize(
	ctx context.Context,
	readWriteBucket storage.ReadWriteBucket,
	options ...InitializeOption,
) error {
	initializeOptions := &initializeOptions{}
	for _, option := range options {
		option(initializeOptions)
	}
	return i.initialize(ctx, readWriteBucket)
}

func (i *initializer) initialize(
	ctx context.Context,
	readWriteBucket storage.ReadWriteBucket,
) error {
	fileInfos, err := i.getFileInfos(ctx, readWriteBucket)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(fileInfos, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func (i *initializer) getFileInfos(
	ctx context.Context,
	readWriteBucket storage.ReadWriteBucket,
) ([]*fileInfo, error) {
	var fileInfos []*fileInfo
	i.forEachFileNode(
		ctx,
		readWriteBucket,
		func(fileNode *ast.FileNode) error {
			fileInfo := &fileInfo{
				Path: fileNode.Name(),
			}
			for _, decl := range fileNode.Decls {
				switch decl := decl.(type) {
				case *ast.ImportNode:
					fileInfo.ImportPaths = append(fileInfo.ImportPaths, decl.Name.AsString())
				}
			}
			fileInfos = append(fileInfos, fileInfo)
			return nil
		},
	)
	return fileInfos, nil
}

func (i *initializer) forEachFileNode(
	ctx context.Context,
	readBucket storage.ReadBucket,
	f func(*ast.FileNode) error,
) error {
	handler := reporter.NewHandler(
		reporter.NewReporter(
			func(reporter.ErrorWithPos) error {
				// never aborts
				return nil
			},
			nil,
		),
	)
	return storage.WalkReadObjects(
		ctx,
		storage.MapReadBucket(
			readBucket,
			storage.MatchPathExt(".proto"),
		),
		"",
		func(readObject storage.ReadObject) error {
			// This can return an error and non-nil AST.
			fileNode, err := parser.Parse(readObject.Path(), readObject, handler)
			if fileNode == nil {
				// No AST implies an I/O error trying to read the file contents. Consider this a real error.
				return err
			}
			if err != nil {
				// There was a syntax error, but we still have a partial AST we can examine.
				i.logger.Debug("syntax_error", zap.String("file_path", readObject.Path()), zap.Error(err))
			}
			return f(fileNode)
		},
	)
}

type fileInfo struct {
	Path        string   `json:"path,omitempty" yaml:"path,omitempty"`
	ImportPaths []string `json:"import_paths,omitempty" yaml:"import_paths,omitempty"`
}

type initializeOptions struct{}
