// Copyright (c) 2018 Cisco and/or its affiliates.
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

// Code generated by informer-gen. DO NOT EDIT.

package v1

import (
	internalinterfaces "github.com/contiv/vpp/plugins/crd/pkg/client/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// CustomConfigurations returns a CustomConfigurationInformer.
	CustomConfigurations() CustomConfigurationInformer
	// CustomNetworks returns a CustomNetworkInformer.
	CustomNetworks() CustomNetworkInformer
	// ExternalInterfaces returns a ExternalInterfaceInformer.
	ExternalInterfaces() ExternalInterfaceInformer
	// IPSecVpnTunnels returns a IPSecVpnTunnelInformer.
	IPSecVpnTunnels() IPSecVpnTunnelInformer
	// SaseServicePolicies returns a SaseServicePolicyInformer.
	SaseServicePolicies() SaseServicePolicyInformer
	// SecurityAssociations returns a SecurityAssociationInformer.
	SecurityAssociations() SecurityAssociationInformer
	// ServiceFunctionChains returns a ServiceFunctionChainInformer.
	ServiceFunctionChains() ServiceFunctionChainInformer
	// SiteResourceGroups returns a SiteResourceGroupInformer.
	SiteResourceGroups() SiteResourceGroupInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// CustomConfigurations returns a CustomConfigurationInformer.
func (v *version) CustomConfigurations() CustomConfigurationInformer {
	return &customConfigurationInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// CustomNetworks returns a CustomNetworkInformer.
func (v *version) CustomNetworks() CustomNetworkInformer {
	return &customNetworkInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// ExternalInterfaces returns a ExternalInterfaceInformer.
func (v *version) ExternalInterfaces() ExternalInterfaceInformer {
	return &externalInterfaceInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// IPSecVpnTunnels returns a IPSecVpnTunnelInformer.
func (v *version) IPSecVpnTunnels() IPSecVpnTunnelInformer {
	return &iPSecVpnTunnelInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// SaseServicePolicies returns a SaseServicePolicyInformer.
func (v *version) SaseServicePolicies() SaseServicePolicyInformer {
	return &saseServicePolicyInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// SecurityAssociations returns a SecurityAssociationInformer.
func (v *version) SecurityAssociations() SecurityAssociationInformer {
	return &securityAssociationInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// ServiceFunctionChains returns a ServiceFunctionChainInformer.
func (v *version) ServiceFunctionChains() ServiceFunctionChainInformer {
	return &serviceFunctionChainInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// SiteResourceGroups returns a SiteResourceGroupInformer.
func (v *version) SiteResourceGroups() SiteResourceGroupInformer {
	return &siteResourceGroupInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}
