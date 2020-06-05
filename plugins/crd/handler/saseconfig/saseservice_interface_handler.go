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

//go:generate protoc -I ./model --go_out=plugins=grpc:./model ./model/saseserviceinterface.proto

package saseconfiguration

import (
	"errors"
	"fmt"
	"strings"

	"github.com/contiv/vpp/plugins/crd/handler/kvdbreflector"
	"github.com/contiv/vpp/plugins/crd/handler/saseconfig/model"
	v1 "github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"go.ligato.io/cn-infra/v2/logging"
)

// SaseServiceInterfaceHandler implements the Handler interface for CRD<->KVDB Reflector.
type SaseServiceInterfaceHandler struct {
	Log       logging.Logger
	CrdClient *crdClientSet.Clientset
}

// CrdName returns name of the CRD.
func (h *SaseServiceInterfaceHandler) CrdName() string {
	return "SaseServiceInterface"
}

// CrdKeyPrefix returns the longest-common prefix under which the instances
// of the given CRD are reflected into KVDB.
func (h *SaseServiceInterfaceHandler) CrdKeyPrefix() (prefix string, underKsrPrefix bool) {
	return model.SaseServiceInterfaceKey + "/", true
}

// IsCrdKeySuffix excludes the KSR-reflected data.
func (h *SaseServiceInterfaceHandler) IsCrdKeySuffix(keySuffix string) bool {
	return !strings.HasPrefix(keySuffix, "contiv-ksr/")
}

// CrdObjectToKVData converts the K8s representation of SrConfiguration into the
// corresponding configuration for vpp-agent(s) running in the destination microservice(s).
func (h *SaseServiceInterfaceHandler) CrdObjectToKVData(obj interface{}) (data []kvdbreflector.KVData, err error) {
	config, ok := obj.(*v1.SaseServiceInterface)
	fmt.Println("CrdObjectToKVData: ", config)
	if !ok {
		return nil, errors.New("failed to cast into SaseServiceInterface struct")
	}
	data = []kvdbreflector.KVData{
		{
			ProtoMsg:  h.convertSaseServiceInterfaceCrdToProto(config),
			KeySuffix: config.GetName(),
		},
	}
	fmt.Println("CrdObjectToKVData: proto data", data)
	return
}

// convertIPSecVpnTunnelCrdToProto:: Convert sase interface crd config to protobuf
func (h *SaseServiceInterfaceHandler) convertSaseServiceInterfaceCrdToProto(crd *v1.SaseServiceInterface) *model.SaseServiceInterface {
	saseIntfpb := &model.SaseServiceInterface{
		InterfaceName:          crd.GetName(),
		ServiceInstanceName: crd.Spec.ServiceInstanceName,
		InterfaceType: crd.Spec.InterfaceType,
		InterfaceMode:      crd.Spec.InterfaceMode,
		InterfaceL3Address: crd.Spec.InterfaceL3Address,
		InterfaceParent: 		 crd.Spec.InterfaceParent,
	}
	return saseIntfpb
}

// IsExclusiveKVDB returns false - there can be multiple writers of the agent configuration in the database.
func (h *SaseServiceInterfaceHandler) IsExclusiveKVDB() bool {
	return false
}

// PublishCrdStatus updates the resource Status information.
func (h *SaseServiceInterfaceHandler) PublishCrdStatus(obj interface{}, opRetval error) error {
	config, ok := obj.(*v1.SaseServiceInterface)
	if !ok {
		return errors.New("failed to cast into SaseServiceInterface struct")
	}
	config = config.DeepCopy()
	if opRetval == nil {
		config.Status.Status = v1.StatusSuccess
	} else {
		config.Status.Status = v1.StatusFailure
		config.Status.Message = opRetval.Error()
	}
	_, err := h.CrdClient.ContivppV1().SaseServiceInterfaces(config.Namespace).Update(config)
	return err
}

// SaseServiceInterfaceValidation generates OpenAPIV3 validator for Sase Service Interface CRD
func SaseServiceInterfaceValidation() *apiextv1beta1.CustomResourceValidation {
	validation := &apiextv1beta1.CustomResourceValidation{
		OpenAPIV3Schema: &apiextv1beta1.JSONSchemaProps{
			Required: []string{"spec"},
			Type:     "object",
			Properties: map[string]apiextv1beta1.JSONSchemaProps{
				"spec": {
					Type:     "object",
					Required: []string{"service","interfacetype","interfacemode"},
					Properties: map[string]apiextv1beta1.JSONSchemaProps{
						"service": {
							Type: "string",
						},	
						"interfacename": {
							Type: "string",
						},
						"interfacemode": {
							Type: "string",
							Enum: []apiextv1beta1.JSON{
								{
									Raw: []byte(`"layer2"`),
								},
								{
									Raw: []byte(`"layer3"`),
								},
							},
						},
						"interfacel3address": {
							Type:        "string",
							Description: "IPv4 or IPv6 address",
							Pattern:     `^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`,
						},
						"interfacetype": {
							Type: "string",
							Enum: []apiextv1beta1.JSON{
								{
									Raw: []byte(`"tap"`),
								},
								{
									Raw: []byte(`"veth"`),
								},
								{
									Raw: []byte(`"memif"`),
								},
							},
						},
					},
				},
			},
		},
	}
	return validation
}

// SaseServiceInterfaceColumns for custom printer columns in the crd
func SaseServiceInterfaceColumns() []apiextv1beta1.CustomResourceColumnDefinition {

	// Printer Columns array
	pc := []apiextv1beta1.CustomResourceColumnDefinition{
		{
			Name:     "Service",
			Type:     "string",
			JSONPath: ".spec.service",
		},
		{
			Name:     "InterfaceName",
			Type:     "string",
			JSONPath: ".spec.interfacename",
		},
		{
			Name:     "InterfaceType",
			Type:     "string",
			JSONPath: ".spec.interfacetype",
		},
		{
			Name:     "InterfaceMode",
			Type:     "string",
			JSONPath: ".spec.interfacemode",
		},
		{
			Name:     "InterfaceL3Address",
			Type:     "string",
			JSONPath: ".spec.interfacel3address",
		},
	}
	return pc
}