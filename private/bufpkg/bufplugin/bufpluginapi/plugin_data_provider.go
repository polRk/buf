// Copyright 2020-2024 Buf Technologies, Inc.
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

package bufpluginapi

import (
	"context"
	"log/slog"

	pluginv1beta1 "buf.build/gen/go/bufbuild/registry/protocolbuffers/go/buf/registry/plugin/v1beta1"
	"connectrpc.com/connect"
	"github.com/bufbuild/buf/private/bufpkg/bufapi"
	"github.com/bufbuild/buf/private/bufpkg/bufplugin"
	"github.com/bufbuild/buf/private/pkg/slicesext"
	"github.com/bufbuild/buf/private/pkg/syserror"
	"github.com/google/uuid"
)

// NewPluginDataProvider returns a new PluginDataProvider for the given API client.
//
// A warning is printed to the logger if a given Plugin is deprecated.
func NewPluingDataProvider(
	logger *slog.Logger,
	clientProvider interface {
		bufapi.PluginV1Beta1DownloadServiceClientProvider
		bufapi.PluginV1Beta1PluginServiceClientProvider
	},
) bufplugin.PluginDataProvider {
	return newPluginDataProvider(logger, clientProvider)
}

// *** PRIVATE ***

type pluginDataProvider struct {
	logger         *slog.Logger
	clientProvider interface {
		bufapi.PluginV1Beta1DownloadServiceClientProvider
		bufapi.PluginV1Beta1PluginServiceClientProvider
	}
}

func newPluginDataProvider(
	logger *slog.Logger,
	clientProvider interface {
		bufapi.PluginV1Beta1DownloadServiceClientProvider
		bufapi.PluginV1Beta1PluginServiceClientProvider
	},
) *pluginDataProvider {
	return &pluginDataProvider{
		logger:         logger,
		clientProvider: clientProvider,
	}
}

func (p *pluginDataProvider) GetPluginDatasForPluginKeys(
	ctx context.Context,
	pluginKeys []bufplugin.PluginKey,
) ([]bufplugin.PluginData, error) {
	if len(pluginKeys) == 0 {
		return nil, nil
	}
	// TODO(ed): check unique digests.
	// TODO(ed): check unique full names.

	registryToIndexedPluginKeys := slicesext.ToIndexedValuesMap(
		pluginKeys,
		func(pluginKey bufplugin.PluginKey) string {
			return pluginKey.PluginFullName().Registry()
		},
	)
	indexedPluginDatas := make([]slicesext.Indexed[bufplugin.PluginData], 0, len(pluginKeys))
	for registry, indexedPluginKeys := range registryToIndexedPluginKeys {
		indexedRegistryPluginDatas, err := p.getIndexedPluginDatasForRegistryAndIndexedPluginKeys(
			ctx,
			registry,
			indexedPluginKeys,
		)
		if err != nil {
			return nil, err
		}
		indexedPluginDatas = append(indexedPluginDatas, indexedRegistryPluginDatas...)
	}
	return slicesext.IndexedToSortedValues(indexedPluginDatas), nil
}

func (p *pluginDataProvider) getIndexedPluginDatasForRegistryAndIndexedPluginKeys(
	ctx context.Context,
	registry string,
	indexedPluginKeys []slicesext.Indexed[bufplugin.PluginKey],
) ([]slicesext.Indexed[bufplugin.PluginData], error) {
	values := slicesext.Map(indexedPluginKeys, func(indexedPluginKey slicesext.Indexed[bufplugin.PluginKey]) *pluginv1beta1.DownloadRequest_Value {
		resourceRefName := &pluginv1beta1.ResourceRef_Name{
			Owner:  indexedPluginKey.Value.PluginFullName().Owner(),
			Plugin: indexedPluginKey.Value.PluginFullName().Name(),
			Child: &pluginv1beta1.ResourceRef_Name_Ref{
				Ref: indexedPluginKey.Value.CommitID().String(),
			},
		}
		return &pluginv1beta1.DownloadRequest_Value{
			ResourceRef: &pluginv1beta1.ResourceRef{
				Value: &pluginv1beta1.ResourceRef_Name_{
					Name: resourceRefName,
				},
			},
		}
	})

	pluginResponse, err := p.clientProvider.PluginV1Beta1DownloadServiceClient(registry).Download(
		ctx,
		connect.NewRequest(&pluginv1beta1.DownloadRequest{
			Values: values,
		}),
	)
	if err != nil {
		return nil, err
	}
	pluginContents := pluginResponse.Msg.Contents
	if len(pluginContents) != len(indexedPluginKeys) {
		return nil, syserror.New("did not get the expected number of plugin datas")
	}

	commitIDToIndexedPluginKeys, err := slicesext.ToUniqueValuesMapError(
		indexedPluginKeys,
		func(indexedPluginKey slicesext.Indexed[bufplugin.PluginKey]) (uuid.UUID, error) {
			return indexedPluginKey.Value.CommitID(), nil
		},
	)
	if err != nil {
		return nil, err
	}

	indexedPluginDatas := make([]slicesext.Indexed[bufplugin.PluginData], 0, len(indexedPluginKeys))
	for _, pluginContent := range pluginContents {
		commitID, err := uuid.Parse(pluginContent.Commit.Id)
		if err != nil {
			return nil, err
		}
		indexedPluginKey, ok := commitIDToIndexedPluginKeys[commitID]
		if !ok {
			return nil, syserror.Newf("did not get plugin key from store with commitID %q", commitID)
		}
		// TODO(ed): handle compression.
		data := pluginContent.Content

		pluginData, err := bufplugin.NewPluginData(
			ctx, indexedPluginKey.Value, func() ([]byte, error) {
				// TODO: handle compression here?
				return data, nil
			},
		)
		if err != nil {
			return nil, err
		}
		indexedPluginDatas = append(
			indexedPluginDatas,
			slicesext.Indexed[bufplugin.PluginData]{
				Value: pluginData,
				Index: indexedPluginKey.Index,
			},
		)
	}
	return indexedPluginDatas, nil
}
