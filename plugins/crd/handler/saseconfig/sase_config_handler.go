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

//go:generate protoc -I ./model --gogo_out=plugins=grpc:./model ./model/saseconfig.proto

package saseconfiguration

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/api/genericmanager"

	"github.com/contiv/vpp/plugins/crd/handler/kvdbreflector"
	v1 "github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
)

// Handler implements the Handler interface for CRD<->KVDB Reflector.
type Handler struct {
	Log       logging.Logger
	CrdClient *crdClientSet.Clientset
}

// CrdName returns name of the CRD.
func (h *Handler) CrdName() string {
	return "SrConfiguration"
}

// CrdKeyPrefix returns the longest-common prefix under which the instances
// of the given CRD are reflected into KVDB.
func (h *Handler) CrdKeyPrefix() (prefix string, underKsrPrefix bool) {
	return "/vnf-agent/", false
}

// IsCrdKeySuffix excludes the KSR-reflected data.
func (h *Handler) IsCrdKeySuffix(keySuffix string) bool {
	return !strings.HasPrefix(keySuffix, "contiv-ksr/")
}

// CrdObjectToKVData converts the K8s representation of SrConfiguration into the
// corresponding configuration for vpp-agent(s) running in the destination microservice(s).
func (h *Handler) CrdObjectToKVData(obj interface{}) (data []kvdbreflector.KVData, err error) {
	saseConfig, ok := obj.(*v1.SrConfiguration)
	fmt.Println("CrdObjectToKVData: ", saseConfig)
	if !ok {
		return nil, errors.New("failed to cast into SaseConfiguration struct")
	}
	return
}

type withName struct {
	Name string `json:"name"`
}

func (h *Handler) configItemToKVData(item v1.SrConfigurationItem, globalMs string) (kvdata kvdbreflector.KVData, err error) {
	var modelSpec *genericmanager.ModelInfo
	fmt.Println("CrdObjectToKVData: ", modelSpec)
	return kvdata, nil
}

// IsExclusiveKVDB returns false - there can be multiple writers of the agent configuration in the database.
func (h *Handler) IsExclusiveKVDB() bool {
	return false
}

// PublishCrdStatus updates the resource Status information.
func (h *Handler) PublishCrdStatus(obj interface{}, opRetval error) error {
	saseConfig, ok := obj.(*v1.SrConfiguration)
	if !ok {
		return errors.New("failed to cast into SaseConfiguration struct")
	}
	saseConfig = saseConfig.DeepCopy()
	if opRetval == nil {
		saseConfig.Status.Status = v1.StatusSuccess
	} else {
		saseConfig.Status.Status = v1.StatusFailure
		saseConfig.Status.Message = opRetval.Error()
	}
	_, err := h.CrdClient.ContivppV1().SrConfigurations(saseConfig.Namespace).Update(saseConfig)
	return err
}

// Validation generates OpenAPIV3 validator for SaseConfiguration CRD
func Validation() *apiextv1beta1.CustomResourceValidation {
	validation := &apiextv1beta1.CustomResourceValidation{
		OpenAPIV3Schema: &apiextv1beta1.JSONSchemaProps{
			Required: []string{"spec"},
			Type:     "object",
			Properties: map[string]apiextv1beta1.JSONSchemaProps{
				"spec": {
					Type:     "object",
					Required: []string{"configItems"},
					Properties: map[string]apiextv1beta1.JSONSchemaProps{
						"configItems": {
							Type: "array",
							Items: &apiextv1beta1.JSONSchemaPropsOrArray{
								Schema: &apiextv1beta1.JSONSchemaProps{
									Type:     "object",
									Required: []string{"module", "type", "data"},
									Properties: map[string]apiextv1beta1.JSONSchemaProps{
										"module": {
											Type: "string",
										},
										"type": {
											Type: "string",
										},
										"data": {
											Type: "string",
										},
										"name": {
											Type: "string",
										},
										"version": {
											Type: "string",
										},
										"microservice": {
											Type: "string",
										},
									},
								},
							},
						},
						"microservice": {
							Type: "string",
						},
					},
				},
			},
		},
	}
	return validation
}
