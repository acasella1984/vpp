// Copyright (c) 2019 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// StatusSuccess is returned in Status.Status when controller successfully creates/deletes/updates CRD.
	StatusSuccess = "Success"
	// StatusFailure is returned in Status.Status when controller fails to create/delete/update CRD.
	StatusFailure = "Failure"
)

// CustomNetwork define custom network for contiv/vpp
// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CustomNetwork struct {
	// TypeMeta is the metadata for the resource, like kind and apiversion
	meta_v1.TypeMeta `json:",inline"`
	// ObjectMeta contains the metadata for the particular object
	meta_v1.ObjectMeta `json:"metadata,omitempty"`
	// Spec is the custom resource spec
	Spec CustomNetworkSpec `json:"spec"`
	// Status informs about the status of the resource.
	Status meta_v1.Status `json:"status,omitempty"`
}

// CustomNetworkSpec is the spec for custom network configuration resource
type CustomNetworkSpec struct {
	Type                   string `json:"type"`
	SubnetCIDR             string `json:"subnetCIDR"`
	SubnetOneNodePrefixLen uint32 `json:"subnetOneNodePrefixLen"`
}

// CustomNetworkList is a list of CustomNetwork resources
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CustomNetworkList struct {
	meta_v1.TypeMeta `json:",inline"`
	meta_v1.ListMeta `json:"metadata"`

	Items []CustomNetwork `json:"items"`
}

// ExternalInterface is used to store definition of an external interface defined via CRD.
// It is a logical entity that may mean different physical interfaces on different nodes.
// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ExternalInterface struct {
	// TypeMeta is the metadata for the resource, like kind and apiversion
	meta_v1.TypeMeta `json:",inline"`
	// ObjectMeta contains the metadata for the particular object
	meta_v1.ObjectMeta `json:"metadata,omitempty"`
	// Spec is the custom resource spec
	Spec ExternalInterfaceSpec `json:"spec"`
	// Status informs about the status of the resource.
	Status meta_v1.Status `json:"status,omitempty"`
}

// ExternalInterfaceSpec is the spec for external interface configuration resource
type ExternalInterfaceSpec struct {
	Type    string          `json:"type"`
	Network string          `json:"network"`
	Nodes   []NodeInterface `json:"nodes"`
}

// NodeInterface describe config for an interface referenced by logical name on a node
type NodeInterface struct {
	Node             string `json:"node"`
	VppInterfaceName string `json:"vppInterfaceName"`
	IP               string `json:"ip"`
	VLAN             uint32 `json:"vlan"`
}

// ExternalInterfaceList is a list of ExternalInterface resources
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ExternalInterfaceList struct {
	meta_v1.TypeMeta `json:",inline"`
	meta_v1.ListMeta `json:"metadata"`

	Items []ExternalInterface `json:"items"`
}

// ServiceFunctionChain define service function chain crd for contiv/vpp
// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ServiceFunctionChain struct {
	// TypeMeta is the metadata for the resource, like kind and apiversion
	meta_v1.TypeMeta `json:",inline"`
	// ObjectMeta contains the metadata for the particular object
	meta_v1.ObjectMeta `json:"metadata,omitempty"`
	// Spec is the custom resource spec
	Spec ServiceFunctionChainSpec `json:"spec"`
	// Status informs about the status of the resource.
	Status meta_v1.Status `json:"status,omitempty"`
}

// ServiceFunctionChainSpec describe service function chain
type ServiceFunctionChainSpec struct {
	Unidirectional bool              `json:"unidirectional"`
	Network        string            `json:"network"`
	Chain          []ServiceFunction `json:"chain"`
}

// ServiceFunction describes single segment of the chain
type ServiceFunction struct {
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	PodSelector     map[string]string `json:"podSelector"`
	Interface       string            `json:"interface"`
	InputInterface  string            `json:"inputInterface"`
	OutputInterface string            `json:"outputInterface"`
}

// ServiceFunctionChainList is a list of ServiceFunctionChain resources
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ServiceFunctionChainList struct {
	meta_v1.TypeMeta `json:",inline"`
	meta_v1.ListMeta `json:"metadata"`

	Items []ServiceFunctionChain `json:"items"`
}

// CustomConfiguration defines (arbitrary) configuration to be applied for
// contiv/vpp or for CNFs running on top of contiv/vpp.
// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CustomConfiguration struct {
	// TypeMeta is the metadata for the resource, like kind and apiversion
	meta_v1.TypeMeta `json:",inline"`
	// ObjectMeta contains the metadata for the particular object
	meta_v1.ObjectMeta `json:"metadata,omitempty"`
	// Spec is the specification for the custom configuration.
	Spec CustomConfigurationSpec `json:"spec"`
	// Status informs about the status of the resource.
	Status meta_v1.Status `json:"status,omitempty"`
}

// CustomConfigurationSpec is the spec for Sase Service configuration resource
type CustomConfigurationSpec struct {
	// Microservice label determines where the configuration item should be applied.
	// For Contiv/VPP vswitch use the hostname of the destination node, otherwise use
	// label as defined in the environment variable MICROSERVICE_LABEL of the
	// destination pod.
	// This microservice label will be used for all items in the list below which do not have microservice defined.
	Microservice string `json:"microservice"`
	// Items is a list of configuration items.
	ConfigItems []ConfigurationItem `json:"configItems"`
}

// ConfigurationItem is the specification for a single Sase service configuration item
type ConfigurationItem struct {
	// Microservice label determines where the configuration item should be applied.
	// For Contiv/VPP vswitch use the hostname of the destination node, otherwise use
	// label as defined in the environment variable MICROSERVICE_LABEL of the
	// destination pod.
	// Microservice label defined at the level of an individual item overwrites the "crd-global" microservice
	// defined under spec.
	Microservice string `json:"microservice"`

	// Module is the name of the module to which the item belongs (e.g. "vpp.nat", "vpp.l2", "linux.l3", etc.).
	Module string `json:"module"`

	// Type of the item (e.g. "dnat44", "acl", "bridge-domain").
	Type string `json:"type"`

	// Version of the configuration (e.g. "v1", "v2", ...).
	// This field is optional - for core vpp-agent configuration items (i.e. shipped with the agent) the version
	// is read from the installed module and for external modules "v1" is assumed as the default.
	Version string `json:"version"`

	// Name of the configuration item.
	// This field is optional - for core vpp-agent configuration items (i.e. shipped with the agent) the name is
	// determined dynamically using the installed module and the configuration of the item (passed in <Data>).
	// For external modules, the name can be omitted if <Data> contains a top-level "Name" field and this would be just
	// a duplication of it.
	Name string `json:"name"`

	// Data should be a YAML-formatted configuration of the item.
	Data string `json:"data"`
}

// CustomConfigurationList is a list of CustomConfiguration resources
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CustomConfigurationList struct {
	meta_v1.TypeMeta `json:",inline"`
	meta_v1.ListMeta `json:"metadata"`
	Items            []CustomConfiguration `json:"items"`
}

// SaseServicePolicy defines service policy definitioons to be applied for
// for trafic handles by a Sase Service.
// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SaseServicePolicy struct {
	// TypeMeta is the metadata for the resource, like kind and apiversion
	meta_v1.TypeMeta `json:",inline"`
	// ObjectMeta contains the metadata for the particular object
	meta_v1.ObjectMeta `json:"metadata,omitempty"`
	// Spec is the specification for the Sase Service configuration.
	Spec SaseServicePolicySpec `json:"spec"`
	// Status informs about the status of the resource.
	Status meta_v1.Status `json:"status,omitempty"`
}

// SaseServicePolicySpec is the spec for Sase Service Policy resource
type SaseServicePolicySpec struct {
	// Sase Service Instance Name
	ServiceInstanceName string `json:"service"`
	// List of Policy Rules.
	Config []SasePolicyRule `json:"config"`
}

// SasePolicyMatch specifies match conditions for a policy to be applied
type SasePolicyMatch struct {
	Protocol        string `json:"protocol"`
	ProtocolPort    uint32 `json:"protocolport"`
	SourceCIDR      string `json:"sourcecidr"`
	DestinationCIDR string `json:"destinationcidr"`
	Port            string `json:"port"`
}

// SasePolicyAction specifies action to be taken when a policy match happens
type SasePolicyAction struct {
	Action string `json:"action"`
}

// SasePolicyRule is the specification for a sase service configuration item
type SasePolicyRule struct {
	Direction string           `json:"direction"`
	Match     SasePolicyMatch  `json:"match"`
	Action    SasePolicyAction `json:"action"`
}

// SaseServicePolicyList is a list of SasePolicy
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SaseServicePolicyList struct {
	meta_v1.TypeMeta `json:",inline"`
	meta_v1.ListMeta `json:"metadata"`
	Items            []SaseServicePolicy `json:"items"`
}

// SiteResourceGroup is grouping of all the resources that exists in a site/location
// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SiteResourceGroup struct {
	// TypeMeta is the metadata for the resource, like kind and apiversion
	meta_v1.TypeMeta `json:",inline"`
	// ObjectMeta contains the metadata for the particular object
	meta_v1.ObjectMeta `json:"metadata,omitempty"`
	// Spec is the specification for the SiteResourceGroup
	Spec SiteResourceGroupSpec `json:"spec"`
	// Status informs about the status of the resource.
	Status meta_v1.Status `json:"status,omitempty"`
}

// SiteResourceGroupSpec is the spec for a SiteResourceGroup
type SiteResourceGroupSpec struct {
	// Local Networks
	LocalNetworks []NetworkInfo `json:"localnetworks"`
	PublicIP      []NetworkInfo `json:"publicip"`
}

// NetworkInfo specifies Networks in a SiteResourceGroup
// NetworkType (Private, PublicNonSecure, PublicSecure)
type NetworkInfo struct {
	Name        string `json:"name"`
	NetworkCIDR string `json:"networkcidr"`
	NetworkType string `json:"networktype"`
}

// SiteResourceGroupList is a list of SiteResourceGroup
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SiteResourceGroupList struct {
	meta_v1.TypeMeta `json:",inline"`
	meta_v1.ListMeta `json:"metadata"`
	Items            []SiteResourceGroup `json:"items"`
}

// SaseSecurityAssociation defines security attributes (algorithms and security keys) between
// networks for secure communication
// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SaseSecurityAssociation struct {
	// TypeMeta is the metadata for the resource, like kind and apiversion
	meta_v1.TypeMeta `json:",inline"`
	// ObjectMeta contains the metadata for the particular object
	meta_v1.ObjectMeta `json:"metadata,omitempty"`
	// Spec is the specification for the SaseSecurityAssociation
	Spec SaseSecurityAssociationSpec `json:"spec"`
	// Status informs about the status of the resource.
	Status meta_v1.Status `json:"status,omitempty"`
}

// SaseSecurityAssociationSpec is the spec for a SaseSecurityAssociation
// Auth and Encrypt algos can be changed to enum - TBD
type SaseSecurityAssociationSpec struct {
	// Sase Service Instance Name
	ServiceInstanceName string `json:"service"`
	// Authentication algorith and key
	AuthAlgo string `json:"authalgo"`
	AuthKey  string `json:"authkey"`
	// Encryption algorithm and key
	EncryptAlgo string `json:"encryptalgo"`
	EncryptKey  string `json:"encryptkey"`
	// Tunnel Mode or Transport Mode
	Mode string `json:"mode"`
}

// SaseSecurityAssociationList is a list of SaseSecurityAssociations
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SaseSecurityAssociationList struct {
	meta_v1.TypeMeta `json:",inline"`
	meta_v1.ListMeta `json:"metadata"`
	Items            []SaseSecurityAssociation `json:"items"`
}

// IPSecVpnTunnel defines IPSec VPN Tunnel attributes for secure site-site communication
// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type IPSecVpnTunnel struct {
	// TypeMeta is the metadata for the resource, like kind and apiversion
	meta_v1.TypeMeta `json:",inline"`
	// ObjectMeta contains the metadata for the particular object
	meta_v1.ObjectMeta `json:"metadata,omitempty"`
	// Spec is the specification for the SiteResourceGroup
	Spec IPSecVpnTunnelSpec `json:"spec"`
	// Status informs about the status of the resource.
	Status meta_v1.Status `json:"status,omitempty"`
}

// IPSecVpnTunnelSpec is the spec for a IPSecVpnTunnel
// Multi-Point tunnels support is available to avoid scale issues. Note
type IPSecVpnTunnelSpec struct {
	// Sase Service Instance Name
	ServiceInstanceName string `json:"service"`
	// Tunnel Destination IP
	DestinationIP string `json:"destinationip"`
	// Tunnel Source IP
	SourceIP string `json:"sourceip"`
	// Reference to security association cro name
	SecurityAssociation string `json:"securityassociation"`
}

// IPSecVpnTunnelList is a list of IPSecVpnTunnel
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type IPSecVpnTunnelList struct {
	meta_v1.TypeMeta `json:",inline"`
	meta_v1.ListMeta `json:"metadata"`
	Items            []IPSecVpnTunnel `json:"items"`
}
