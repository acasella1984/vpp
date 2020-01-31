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

	"github.com/contiv/vpp/plugins/crd/handler/kvdbreflector"
	"github.com/contiv/vpp/plugins/crd/handler/saseconfig/model"
	v1 "github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	"github.com/ligato/cn-infra/logging"
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
	return model.Keyword + "/", true
}

// IsCrdKeySuffix excludes the KSR-reflected data.
func (h *Handler) IsCrdKeySuffix(keySuffix string) bool {
	return !strings.HasPrefix(keySuffix, "contiv-ksr/")
}

// CrdObjectToKVData converts the K8s representation of SrConfiguration into the
// corresponding configuration for vpp-agent(s) running in the destination microservice(s).
func (h *Handler) CrdObjectToKVData(obj interface{}) (data []kvdbreflector.KVData, err error) {
	saseConfig, ok := obj.(*v1.SaseServicePolicy)
	fmt.Println("CrdObjectToKVData: ", saseConfig)
	if !ok {
		return nil, errors.New("failed to cast into SaseConfiguration struct")
	}
	data = []kvdbreflector.KVData{
		{
			ProtoMsg:  h.saseConfigCrdToProto(saseConfig),
			KeySuffix: saseConfig.GetName(),
		},
	}
	fmt.Println("CrdObjectToKVData: proto data", data)
	return
}

type withName struct {
	Name string `json:"name"`
}

// convertSaseServiceNameToProto:: get the sase service name
// VENKAT: TBD
func convertSaseServiceNameToProto(name string) model.SaseConfig_SaseService {
	return model.SaseConfig_Firewall
}

// saseConfigCrdToProto:: Convert sase crd config to protobuf
// VENKAT: TBD.  curreeeeeeeeeeeeently hardcoded the values for testing
func (h *Handler) saseConfigCrdToProto(crd *v1.SaseServicePolicy) *model.SaseConfig {

	// Convert config recieved in crd to protobuf
	scPb := &model.SaseConfig{
		Name:        crd.GetName(),
		SaseService: convertSaseServiceNameToProto(crd.Spec.Service),
		Direction:   model.SaseConfig_Egress,
		Match: &model.SaseConfig_Match{
			Proto: model.SaseConfig_Match_UDP,
		},
		Action: model.SaseConfig_PERMIT,
	}

	fmt.Println("saseConfigCrdToProto ", scPb)
	return scPb
}

// IsExclusiveKVDB returns false - there can be multiple writers of the agent configuration in the database.
func (h *Handler) IsExclusiveKVDB() bool {
	return false
}

// PublishCrdStatus updates the resource Status information.
func (h *Handler) PublishCrdStatus(obj interface{}, opRetval error) error {
	saseConfig, ok := obj.(*v1.SaseServicePolicy)
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
	_, err := h.CrdClient.ContivppV1().SaseServicePolicies(saseConfig.Namespace).Update(saseConfig)
	return err
}

// Validation generates OpenAPIV3 validator for SaseServicePolicy CRD
// VENKAT:: TBD
