/*
 * // Copyright (c) 2020
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

package common

// SaseServiceType : Service Type
type SaseServiceType int

const (
	// ServiceTypeNone :
	ServiceTypeNone = iota
	// ServiceTypeFirewall :
	ServiceTypeFirewall
	// ServiceTypeNAT :
	ServiceTypeNAT
	// ServiceTypeRouting :
	ServiceTypeRouting
	// ServiceTypeIPSecVpn :
	ServiceTypeIPSecVpn // Change to just VPN
)

const (
	// Firewall :
	firewall = "firewall"
	// Nat :
	nat = "nat"
	// Routing :
	routing = "routing"
	// IpsecVpn :
	ipsecVpn = "ipsecvpn"
)

const (
	baseServiceLabel = "vpp-vswitch"
)

// ServiceInfo : ServiceInfo contains all the relevant details of a particular service
// instance being handled by sase plugin on a particular node.
type ServiceInfo struct {
	Name PodSaseServiceInfo
	Pod  *PodInfo
}

// GetBaseVppServices :
func GetBaseVppServices() []PodSaseServiceInfo {
	// Enable Services on the base vpp vswitch pod
	addService := []PodSaseServiceInfo{{serviceID: baseServiceID,
		serviceLocation: baseServiceLocation,
		serviceType:     routing},
		{serviceID: baseServiceID,
			serviceLocation: baseServiceLocation,
			serviceType:     firewall},
		{serviceID: baseServiceID,
			serviceLocation: baseServiceLocation,
			serviceType:     nat}}

	return addService
}

// GetBaseServiceLabel :
func GetBaseServiceLabel() string {
	return baseServiceLabel
}

// GetServiceType : Return Sase Service Type
func (srv *ServiceInfo) GetServiceType() SaseServiceType {

	var serviceType SaseServiceType

	switch srv.Name.serviceType {
	case firewall:
		serviceType = ServiceTypeFirewall
	case nat:
		serviceType = ServiceTypeNAT
	case routing:
		serviceType = ServiceTypeRouting
	case ipsecVpn:
		serviceType = ServiceTypeIPSecVpn
	default:
	}

	return serviceType
}

// GetServicePodLabel : Get CNF Pod Label where Service is deployed
func (srv *ServiceInfo) GetServicePodLabel() string {
	return srv.Pod.GetPodLabel()
}

// GetServiceIngressInterface :
func (srv *ServiceInfo) GetServiceIngressInterface() []PodInterfaceInfo {
	return srv.Pod.GetPodIngressInterface()
}

// GetServiceEgressInterface :
func (srv *ServiceInfo) GetServiceEgressInterface() []PodInterfaceInfo {
	return srv.Pod.GetPodEgressInterface()
}
