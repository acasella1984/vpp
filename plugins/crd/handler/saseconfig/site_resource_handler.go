/*
 * // Copyright (c) 2019 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

//go:generate protoc -I ./model --go_out=plugins=grpc:./model ./model/siteresourcegroup.proto

package saseconfiguration

import (
	"errors"
	"fmt"
	"strings"

	"github.com/contiv/vpp/plugins/crd/handler/kvdbreflector"
	"github.com/contiv/vpp/plugins/crd/handler/saseconfig/model"
	v1 "github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	"go.ligato.io/cn-infra/v2/logging"
)

// SiteResourceGroupHandler implements the Handler interface for CRD<->KVDB Reflector.
type SiteResourceGroupHandler struct {
	Log       logging.Logger
	CrdClient *crdClientSet.Clientset
}

// CrdName returns name of the CRD.
func (h *SiteResourceGroupHandler) CrdName() string {
	return "SiteResourceGroup"
}

// CrdKeyPrefix returns the longest-common prefix under which the instances
// of the given CRD are reflected into KVDB.
func (h *SiteResourceGroupHandler) CrdKeyPrefix() (prefix string, underKsrPrefix bool) {
	return model.SiteResourceGroupKey + "/", true
}

// IsCrdKeySuffix excludes the KSR-reflected data.
func (h *SiteResourceGroupHandler) IsCrdKeySuffix(keySuffix string) bool {
	return !strings.HasPrefix(keySuffix, "contiv-ksr/")
}

// CrdObjectToKVData converts the K8s representation of SiteResourceGroup into the
// corresponding configuration for vpp-agent(s) running in the destination microservice(s).
func (h *SiteResourceGroupHandler) CrdObjectToKVData(obj interface{}) (data []kvdbreflector.KVData, err error) {
	config, ok := obj.(*v1.SiteResourceGroup)
	fmt.Println("CrdObjectToKVData: ", config)
	if !ok {
		return nil, errors.New("failed to cast into SiteResourceGroup struct")
	}
	data = []kvdbreflector.KVData{
		{
			ProtoMsg:  h.siteResourceGroupCrdToProto(config),
			KeySuffix: config.GetName(),
		},
	}
	fmt.Println("CrdObjectToKVData: proto data", data)
	return
}

// siteResourceGroupCrdToProto:: Convert siteResourceGroup to protobuf
func (h *SiteResourceGroupHandler) siteResourceGroupCrdToProto(crd *v1.SiteResourceGroup) *model.SiteResourceGroup {
	srgpb := &model.SiteResourceGroup{
		SiteName: crd.GetName(),
	}

	// Copy local network information
	for _, networkInfo := range crd.Spec.LocalNetworks {
		networkPb := &model.SiteResourceGroup_NetworkInfo{
			Name:        networkInfo.Name,
			NetworkCidr: networkInfo.NetworkCIDR,
			NetworkType: networkInfo.NetworkType,
		}
		srgpb.LocalNetwork = append(srgpb.LocalNetwork, networkPb)
	}

	// Copy Public IP/network information
	for _, networkInfo := range crd.Spec.PublicIP {
		networkPb := &model.SiteResourceGroup_NetworkInfo{
			Name:        networkInfo.Name,
			NetworkCidr: networkInfo.NetworkCIDR,
			NetworkType: networkInfo.NetworkType,
		}
		srgpb.LocalNetwork = append(srgpb.PublicNetwork, networkPb)
	}

	return srgpb
}

// IsExclusiveKVDB returns false - there can be multiple writers of the agent configuration in the database.
func (h *SiteResourceGroupHandler) IsExclusiveKVDB() bool {
	return false
}

// PublishCrdStatus updates the resource Status information.
func (h *SiteResourceGroupHandler) PublishCrdStatus(obj interface{}, opRetval error) error {
	config, ok := obj.(*v1.SiteResourceGroup)
	if !ok {
		return errors.New("failed to cast into SiteResourceGroup struct")
	}
	config = config.DeepCopy()
	if opRetval == nil {
		config.Status.Status = v1.StatusSuccess
	} else {
		config.Status.Status = v1.StatusFailure
		config.Status.Message = opRetval.Error()
	}
	_, err := h.CrdClient.ContivppV1().SiteResourceGroups(config.Namespace).Update(config)
	return err
}

// Validation generates OpenAPIV3 validator for SaseServicePolicy CRD
// VENKAT:: TBD
