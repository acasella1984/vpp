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

//go:generate protoc -I ./model --go_out=plugins=grpc:./model ./model/networkfirewallprofile.proto

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

// NetworkFirewallProfileHandler implements the Handler interface for CRD<->KVDB Reflector.
type NetworkFirewallProfileHandler struct {
	Log       logging.Logger
	CrdClient *crdClientSet.Clientset
}

// CrdName returns name of the CRD.
func (h *NetworkFirewallProfileHandler) CrdName() string {
	return "NetworkFirewallProfile"
}

// CrdKeyPrefix returns the longest-common prefix under which the instances
// of the given CRD are reflected into KVDB.
func (h *NetworkFirewallProfileHandler) CrdKeyPrefix() (prefix string, underKsrPrefix bool) {
	return model.NetworkFirewallProfileKey + "/", true
}

// IsCrdKeySuffix excludes the KSR-reflected data.
func (h *NetworkFirewallProfileHandler) IsCrdKeySuffix(keySuffix string) bool {
	return !strings.HasPrefix(keySuffix, "contiv-ksr/")
}

// CrdObjectToKVData converts the K8s representation of NetworkFirewallProfile into the
// corresponding configuration for vpp-agent(s) running in the destination microservice(s).
func (h *NetworkFirewallProfileHandler) CrdObjectToKVData(obj interface{}) (data []kvdbreflector.KVData, err error) {
	config, ok := obj.(*v1.NetworkFirewallProfile)
	fmt.Println("CrdObjectToKVData: ", config)
	if !ok {
		return nil, errors.New("failed to cast into NetworkFirewallProfile struct")
	}
	data = []kvdbreflector.KVData{
		{
			ProtoMsg:  h.networkFirewallProfileCrdToProto(config),
			KeySuffix: config.GetName(),
		},
	}
	fmt.Println("CrdObjectToKVData: proto data", data)
	return
}

func getFirewallAction(a string) model.NetworkFirewallProfile_FirewallRule_Action {

	if a == deny {
		return model.NetworkFirewallProfile_FirewallRule_DENY
	} else if a == permit {
		return model.NetworkFirewallProfile_FirewallRule_PERMIT_REFLECT
	} 

	return model.NetworkFirewallProfile_FirewallRule_DENY
}

func getProtocolValue(proto string) model.NetworkFirewallProfile_FirewallRule_Proto {

	var protoPb model.NetworkFirewallProfile_FirewallRule_Proto

	switch proto {
	case tcp:
		protoPb = model.NetworkFirewallProfile_FirewallRule_TCP
	case udp:
		protoPb = model.NetworkFirewallProfile_FirewallRule_UDP
	default:
		protoPb = model.NetworkFirewallProfile_FirewallRule_NONE
	}
	return protoPb
}

func getFirewallDirection(dir string) model.NetworkFirewallProfile_Direction {

	if dir == egress {
		return model.NetworkFirewallProfile_EGRESS
	}

	// Default Ingress
	return model.NetworkFirewallProfile_INGRESS
}

func (h *NetworkFirewallProfileHandler) firewallRulesToProto(fwRuleCrd v1.NetworkFirewallRule) *model.NetworkFirewallProfile_FirewallRule {
	fwRule := &model.NetworkFirewallProfile_FirewallRule{
		Name:    fwRuleCrd.Name,
		Protocol: getProtocolValue(fwRuleCrd.Protocol),
		SrcProtoPort: fwRuleCrd.SrcProtocolPort,
		DstProtoPort: fwRuleCrd.DstProtocolPort,
		SourceCidr: fwRuleCrd.SourceCIDR,
		DestinationCidr: fwRuleCrd.DestinationCIDR,
		Action: getFirewallAction(fwRuleCrd.Action),       
	}
	return fwRule
}

// networkFirewallProfileCrdToProto:: Convert networkFirewallProfileCrd to protobuf
func (h *NetworkFirewallProfileHandler) networkFirewallProfileCrdToProto(crd *v1.NetworkFirewallProfile) *model.NetworkFirewallProfile {
	fwp := &model.NetworkFirewallProfile{
		Name:          crd.GetName(),
		ServiceInstanceName: crd.Spec.ServiceInstanceName,
		InterfaceName: crd.Spec.Interface,
		Direction: getFirewallDirection(crd.Spec.Direction),
	}

	// Convert firewall rules associated with the profile
	for _, r := range crd.Spec.Rules{
		fwp.Rules = append(fwp.Rules,
			h.firewallRulesToProto(r))
	}

	return fwp
}

// IsExclusiveKVDB returns false - there can be multiple writers of the agent configuration in the database.
func (h *NetworkFirewallProfileHandler) IsExclusiveKVDB() bool {
	return false
}

// PublishCrdStatus updates the resource Status information.
func (h *NetworkFirewallProfileHandler) PublishCrdStatus(obj interface{}, opRetval error) error {
	config, ok := obj.(*v1.NetworkFirewallProfile)
	if !ok {
		return errors.New("failed to cast into NetworkFirewallProfile struct")
	}
	config = config.DeepCopy()
	if opRetval == nil {
		config.Status.Status = v1.StatusSuccess
	} else {
		config.Status.Status = v1.StatusFailure
		config.Status.Message = opRetval.Error()
	}
	_, err := h.CrdClient.ContivppV1().NetworkFirewallProfiles(config.Namespace).Update(config)
	return err
}

// NetworkFirewallProfileValidation generates OpenAPIV3 validator for NetworkFirewallProfile CRD
func NetworkFirewallProfileValidation() *apiextv1beta1.CustomResourceValidation {
	validation := &apiextv1beta1.CustomResourceValidation{
		OpenAPIV3Schema: &apiextv1beta1.JSONSchemaProps{
			Required: []string{"spec"},
			Type:     "object",
			Properties: map[string]apiextv1beta1.JSONSchemaProps{
				"spec": {
					Type:     "object",
					Required: []string{"service", "rules"},
					Properties: map[string]apiextv1beta1.JSONSchemaProps{
						"name": {
							Type: "string",
						},
						"service": {
							Type: "string",
						},
						"direction": {
							Type: "string",
							Enum: []apiextv1beta1.JSON{
								{
									Raw: []byte(`"Ingress"`),
								},
								{
									Raw: []byte(`"Egress"`),
								},
							},
						},
						"interface": {
							Type: "string",
						},
						"rules": {
							Type: "array",
							Items: &apiextv1beta1.JSONSchemaPropsOrArray{
								Schema: &apiextv1beta1.JSONSchemaProps{
									Type:     "object",
									Required: []string{"action"},
									Properties: map[string]apiextv1beta1.JSONSchemaProps{
										"name": {
											Type: "string",
										},
										"protocol": {
											Type: "string",
											Enum: []apiextv1beta1.JSON{
												{
													Raw: []byte(`"TCP"`),
												},
												{
													Raw: []byte(`"UDP"`),
												},
												{
													Raw: []byte(`"ICMP"`),
												},
											},
										},
										"srcprotocolport": {
											Type: "integer",
										},
										"dstprotocolport": {
											Type: "integer",
										},
										"sourcecidr": {
											Type: "string",
										},
										"destinationcidr": {
											Type: "string",
										},
										"action": {
											Type: "string",
											Enum: []apiextv1beta1.JSON{
												{
													Raw: []byte(`"Deny"`),
												},
												{
													Raw: []byte(`"Permit"`),
												},
											},
										},
									},
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