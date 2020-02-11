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

package processor

import (
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
)

// ServiceInfo : ServiceInfo contains all the relevant details of a particular service
// instance being handled by sase plugin on a particular node.
// Note that a
type ServiceInfo struct {
	Name       podSaseServiceInfo
	PodID      podmodel.ID        // CNF Pod on which service is deployed
	Interfaces []PodInterfaceInfo // PodInterfaces (ingress/egress) for the service context
}

// GetServicePodID : Get CNF PodID where given Service is deployed
func (srv *ServiceInfo) GetServicePodID(name podSaseServiceInfo) podmodel.ID {
	return srv.PodID
}

// GetServiceIngressInterface :
func (srv *ServiceInfo) GetServiceIngressInterface(name podSaseServiceInfo) []PodInterfaceInfo {
	var ingressInterfaces []PodInterfaceInfo
	return ingressInterfaces
}

// GetServiceEgressInterface :
func (srv *ServiceInfo) GetServiceEgressInterface(name podSaseServiceInfo) []PodInterfaceInfo {
	var egressInterfaces []PodInterfaceInfo
	return egressInterfaces
}
