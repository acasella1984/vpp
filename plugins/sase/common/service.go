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

import (
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

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
	// Sase Services type
	firewall = "firewall"
	nat      = "nat"
	routing  = "routing"
	ipsecVpn = "ipsecvpn"
)

// ServiceInfo : ServiceInfo contains all the relevant details of a particular service
// instance being handled by sase plugin on a particular node.
// Note that a
type ServiceInfo struct {
	Name       PodSaseServiceInfo
	PodID      podmodel.ID        // CNF Pod on which service is deployed
	Interfaces []PodInterfaceInfo // PodInterfaces (ingress/egress) for the service context
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

// GetServicePodID : Get CNF PodID where given Service is deployed
func (srv *ServiceInfo) GetServicePodID(name PodSaseServiceInfo) podmodel.ID {
	return srv.PodID
}

// GetServiceIngressInterface :
func (srv *ServiceInfo) GetServiceIngressInterface(name PodSaseServiceInfo) []PodInterfaceInfo {
	var ingressInterfaces []PodInterfaceInfo
	for _, intf := range srv.Interfaces {
		if intf.IsIngress == true {
			ingressInterfaces = append(ingressInterfaces, intf)
		}
	}
	return ingressInterfaces
}

// GetServiceEgressInterface :
func (srv *ServiceInfo) GetServiceEgressInterface(name PodSaseServiceInfo) []PodInterfaceInfo {
	var egressInterfaces []PodInterfaceInfo
	for _, intf := range srv.Interfaces {
		if intf.IsIngress == false {
			egressInterfaces = append(egressInterfaces, intf)
		}
	}
	return egressInterfaces
}
