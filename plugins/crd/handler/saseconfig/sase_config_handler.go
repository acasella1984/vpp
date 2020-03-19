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

//go:generate protoc -I ./model --go_out=plugins=grpc:./model ./model/saseconfig.proto

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

// SaseServicePolicyHandler implements the Handler interface for CRD<->KVDB Reflector.
type SaseServicePolicyHandler struct {
	Log       logging.Logger
	CrdClient *crdClientSet.Clientset
}

// CrdName returns name of the CRD.
func (h *SaseServicePolicyHandler) CrdName() string {
	return "SrConfiguration"
}

// CrdKeyPrefix returns the longest-common prefix under which the instances
// of the given CRD are reflected into KVDB.
func (h *SaseServicePolicyHandler) CrdKeyPrefix() (prefix string, underKsrPrefix bool) {
	return model.SasePolicyKey + "/", true
}

// IsCrdKeySuffix excludes the KSR-reflected data.
func (h *SaseServicePolicyHandler) IsCrdKeySuffix(keySuffix string) bool {
	return !strings.HasPrefix(keySuffix, "contiv-ksr/")
}

// CrdObjectToKVData converts the K8s representation of SrConfiguration into the
// corresponding configuration for vpp-agent(s) running in the destination microservice(s).
func (h *SaseServicePolicyHandler) CrdObjectToKVData(obj interface{}) (data []kvdbreflector.KVData, err error) {
	sasePolicy, ok := obj.(*v1.SaseServicePolicy)
	fmt.Println("CrdObjectToKVData: ", sasePolicy)
	if !ok {
		return nil, errors.New("failed to cast into SaseConfiguration struct")
	}

	data = []kvdbreflector.KVData{
		{
			ProtoMsg:  convertSasePolicyRuleToProto(sasePolicy.Spec),
			KeySuffix: sasePolicy.GetName(),
		},
	}
	fmt.Println("CrdObjectToKVData: proto data", data)
	return
}

/*
// saseServicePolicyCrdToProto:: Convert sase policy crd to protobuf KV
func saseServicePolicyCrdToProto(crd *v1.SaseServicePolicy) (data []kvdbreflector.KVData, err error) {

	for _, policyRule := range crd.Spec.Config {
		// Convert config recieved in crd to protobuf
		// VENKAT: Verify if Policy Name or Policy Rule name for KeySuffix
		scPb := convertSasePolicyRuleToProto(policyRule)
		data = append(data, kvdbreflector.KVData{
			ProtoMsg:  scPb,
			KeySuffix: crd.GetName()})
	}
	return data, nil
} */

// IsExclusiveKVDB returns false - there can be multiple writers of the agent configuration in the database.
func (h *SaseServicePolicyHandler) IsExclusiveKVDB() bool {
	return false
}

// PublishCrdStatus updates the resource Status information.
func (h *SaseServicePolicyHandler) PublishCrdStatus(obj interface{}, opRetval error) error {
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

///////////////// Helper routines for converting CRD attributes to Protobuf attributes /////////////
const (
	// Policy Rule Direction
	egress  = "Egress"
	ingress = "Ingress"

	// Policy Rule Action
	deny    = "Deny"
	permit  = "Permit"
	snat    = "Snat"
	dnat    = "Dnat"
	forward = "Forward"
	secure  = "Secure"

	// Protocol
	tcp = "TCP"
	udp = "UDP"
)

func getPbPolicyDirection(dir string) model.SaseConfig_Direction {

	if dir == egress {
		return model.SaseConfig_Egress
	}

	// Default Ingress
	return model.SaseConfig_Ingress
}

func getPbProto(proto string) model.SaseConfig_Match_Proto {

	var protoPb model.SaseConfig_Match_Proto

	switch proto {
	case tcp:
		protoPb = model.SaseConfig_Match_TCP
	case udp:
		protoPb = model.SaseConfig_Match_UDP
	default:
		protoPb = model.SaseConfig_Match_NONE
	}
	return protoPb
}

func convertSasePolicyRuleMatchToProto(match v1.SasePolicyRuleMatch) *model.SaseConfig_Match {

	// Policy Match Rule in ProtoBuf
	matchPb := &model.SaseConfig_Match{
		InterfaceName: match.Port,
		SourceIp:      match.SourceCIDR,
		DestinationIp: match.DestinationCIDR,
		Protocol:      getPbProto(match.Protocol),
		Port:          match.ProtocolPort,
	}
	return matchPb
}

// VENKAT: Note SNAT and DNAT distinction can be made based on Rule direction. ??
func convertSasePolicyRuleActionToProto(action v1.SasePolicyRuleAction) model.SaseConfig_Action {

	var actPb model.SaseConfig_Action

	switch action.Action {
	case deny:
		actPb = model.SaseConfig_DENY
	case permit:
		actPb = model.SaseConfig_PERMIT
	case snat:
		actPb = model.SaseConfig_SNAT
	case dnat:
		actPb = model.SaseConfig_DNAT
	case forward:
		actPb = model.SaseConfig_FORWARD
	case secure:
		actPb = model.SaseConfig_SECURE
	}
	return actPb
}

// convertSasePolicyRuleToProto
func convertSasePolicyRuleToProto(rule v1.SaseServicePolicySpec) *model.SaseConfig {

	// Convert config recieved in crd to protobuf
	rulePb := &model.SaseConfig{
		Name:                rule.Name,
		ServiceInstanceName: rule.ServiceInstanceName,
		Direction:           getPbPolicyDirection(rule.Direction),
		Match:               convertSasePolicyRuleMatchToProto(rule.Match),
		Action:              convertSasePolicyRuleActionToProto(rule.Action),
	}

	return rulePb
}
