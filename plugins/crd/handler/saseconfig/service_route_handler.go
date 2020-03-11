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

//go:generate protoc -I ./model --gogo_out=plugins=grpc:./model ./model/serviceroute.proto

package saseconfiguration

import (
	"errors"
	"fmt"
	"strings"

	"github.com/contiv/vpp/plugins/crd/handler/kvdbreflector"
	"github.com/contiv/vpp/plugins/crd/handler/saseconfig/model"
	v1 "github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	"github.com/ligato/cn-infra/logging"
)

// ServiceRouteHandler implements the Handler interface for CRD<->KVDB Reflector.
type ServiceRouteHandler struct {
	Log       logging.Logger
	CrdClient *crdClientSet.Clientset
}

// CrdName returns name of the CRD.
func (h *ServiceRouteHandler) CrdName() string {
	return "ServiceRoute"
}

// CrdKeyPrefix returns the longest-common prefix under which the instances
// of the given CRD are reflected into KVDB.
func (h *ServiceRouteHandler) CrdKeyPrefix() (prefix string, underKsrPrefix bool) {
	return model.ServiceRouteKey + "/", true
}

// IsCrdKeySuffix excludes the KSR-reflected data.
func (h *ServiceRouteHandler) IsCrdKeySuffix(keySuffix string) bool {
	return !strings.HasPrefix(keySuffix, "contiv-ksr/")
}

// CrdObjectToKVData converts the K8s representation of SiteResourceGroup into the
// corresponding configuration for vpp-agent(s) running in the destination microservice(s).
func (h *ServiceRouteHandler) CrdObjectToKVData(obj interface{}) (data []kvdbreflector.KVData, err error) {
	config, ok := obj.(*v1.ServiceRoute)
	fmt.Println("CrdObjectToKVData: ", config)
	if !ok {
		return nil, errors.New("failed to cast into ServiceRoute struct")
	}
	data = []kvdbreflector.KVData{
		{
			ProtoMsg:  h.serviceRouteCrdToProto(config),
			KeySuffix: config.GetName(),
		},
	}
	fmt.Println("CrdObjectToKVData: proto data", data)
	return
}

// serviceRouteCrdToProto:: Convert serviceRoute Crd to protobuf
func (h *ServiceRouteHandler) serviceRouteCrdToProto(crd *v1.ServiceRoute) *model.ServiceRoute {
	srpb := &model.ServiceRoute{
		ServiceInstanceName: crd.Spec.ServiceInstanceName,
		DestinationNetwork:  crd.Spec.DestinationNetwork,
		GatewayAddress:      crd.Spec.GatewayIPAddress,
		GatewayServiceId:    crd.Spec.GatewayServiceID,
		GatewayNetwork:      crd.Spec.GatewayNetwork,
		EgressInterface:     crd.Spec.EgressInterface,
	}

	return srpb
}

// IsExclusiveKVDB returns false - there can be multiple writers of the agent configuration in the database.
func (h *ServiceRouteHandler) IsExclusiveKVDB() bool {
	return false
}

// PublishCrdStatus updates the resource Status information.
func (h *ServiceRouteHandler) PublishCrdStatus(obj interface{}, opRetval error) error {
	config, ok := obj.(*v1.ServiceRoute)
	if !ok {
		return errors.New("failed to cast into ServiceRoute struct")
	}
	config = config.DeepCopy()
	if opRetval == nil {
		config.Status.Status = v1.StatusSuccess
	} else {
		config.Status.Status = v1.StatusFailure
		config.Status.Message = opRetval.Error()
	}
	_, err := h.CrdClient.ContivppV1().ServiceRoutes(config.Namespace).Update(config)
	return err
}

// Validation generates OpenAPIV3 validator for SaseServicePolicy CRD
// VENKAT:: TBD
