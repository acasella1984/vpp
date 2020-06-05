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

package model

import "github.com/contiv/vpp/plugins/ksr/model/ksrkey"

const (
	// SasePolicyKey :
	SasePolicyKey = "sasepolicy"
	// SiteResourceGroupKey :
	SiteResourceGroupKey = "siteresourcegroup"
	// SecurityAssociationKey :
	SecurityAssociationKey = "securityassociation"
	// IPSecVpnTunnelKey :
	IPSecVpnTunnelKey = "ipsecvpntunnel"
	// ServiceRouteKey :
	ServiceRouteKey = "serviceroute"
	// NetworkFirewallProfileKey :
	NetworkFirewallProfileKey = "NetworkFirewallProfile"
	// SaseServiceInterfaceKey :
	SaseServiceInterfaceKey = "saseserviceinterfacekey"
)

// KeyPrefixSasePolicy return prefix for Sase Policy
func KeyPrefixSasePolicy() string {
	return ksrkey.KsrK8sPrefix + "/" + SasePolicyKey + "/"
}

// KeyPrefixSiteResourceGroup return prefix for Site Resource Group
func KeyPrefixSiteResourceGroup() string {
	return ksrkey.KsrK8sPrefix + "/" + SiteResourceGroupKey + "/"
}

// KeyPrefixSecurityAssociation return prefix for Security Association
func KeyPrefixSecurityAssociation() string {
	return ksrkey.KsrK8sPrefix + "/" + SecurityAssociationKey + "/"
}

// KeyPrefixIPSecVpnTunnel return prefix for IPSecVpnTunnel
func KeyPrefixIPSecVpnTunnel() string {
	return ksrkey.KsrK8sPrefix + "/" + IPSecVpnTunnelKey + "/"
}

// KeyPrefixServiceRoute return prefix for ServiceRoute
func KeyPrefixServiceRoute() string {
	return ksrkey.KsrK8sPrefix + "/" + ServiceRouteKey + "/"
}

// KeyPrefixNetworkFirewallProfile return prefix for NetworkFirewallProfile
func KeyPrefixNetworkFirewallProfile() string {
	return ksrkey.KsrK8sPrefix + "/" + NetworkFirewallProfileKey + "/"
}

// KeyPrefixSaseServiceInterface return prefix for Sase Service Interface
func KeyPrefixSaseServiceInterface() string {
	return ksrkey.KsrK8sPrefix + "/" + SaseServiceInterfaceKey + "/"
}
