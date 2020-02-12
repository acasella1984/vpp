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

package common

import (
	"fmt"
	"sort"
	"strings"

	"github.com/contiv/vpp/plugins/ksr/model/pod"
)

const (
	contivAnnotationPrefix            = "contivpp.io/"
	contivMicroserviceLabelAnnotation = contivAnnotationPrefix + "microservice-label"  // k8s annotation used to specify microservice label of a pod
	contivServiceEndpointIfAnnotation = contivAnnotationPrefix + "service-endpoint-if" // k8s annotation used to specify k8s service endpoint interface
	contivCustomIfAnnotation          = contivAnnotationPrefix + "custom-if"           // k8s annotation used to request custom pod interfaces
	contivSaseServiceAnnotation       = contivAnnotationPrefix + "sase-service"        // k8s annotation used to specify sase service deplyed on the pod
	contivNamesSeparator              = ","                                            // separator used to split multiple interfaces in k8s annotation

	memifIfType = "memif"
	tapIfType   = "tap"
	vethIfType  = "veth"
)

// PodSaseServiceInfo holds information about a Sase Service Instance deployed on a Pod
// There could be multiple instances of same service in a service location
type PodSaseServiceInfo struct {
	serviceID       string
	serviceLocation string
	serviceType     string
}

// PodInfo : Relevant Pod Information
type PodInfo struct {
	ID          pod.ID
	Label       string // Microservice Label
	Interfaces  []PodInterfaceInfo
	ServiceList []PodSaseServiceInfo
}

// InterfaceMode : Operating mode of Interface
type InterfaceMode int

const (
	// L2 : L2 Mode
	L2 InterfaceMode = iota
	// L3 : L3 Mode
	L3
	// VxLan : Vxlan Tunnel Interface
	VxLan
	// IPSec : IpSec Tunnel Interface
	IPSec
)

// PodInterfaceInfo : Pod Interface represents the ingress/egress interfaces
// of a CNF Pod where services are deployed
type PodInterfaceInfo struct {
	Name         string // Identified outside in abstractions
	InternalName string // Represented in datapath if different
	Type         string
	Mode         InterfaceMode
	IPAddress    string
	MacAddress   string
	IsIngress    bool // IsIngress (true) would mean local network facing ingress interface
}

// GetContivMicroserviceLabel returns microservice label defined in pod annotations
// (or an empty string if it is not defined).
func GetContivMicroserviceLabel(annotations map[string]string) string {
	for k, v := range annotations {
		if strings.HasPrefix(k, contivMicroserviceLabelAnnotation) {
			return v
		}
	}
	return ""
}

// getContivServiceEndpointIf returns service endpoint interface defined in pod annotations
// (or an empty string if it is not defined).
func getContivServiceEndpointIf(annotations map[string]string) string {
	for k, v := range annotations {
		if strings.HasPrefix(k, contivServiceEndpointIfAnnotation) {
			return v
		}
	}
	return ""
}

// hasContivCustomIfAnnotation returns true if provided annotations contain contiv custom-if annotation, false otherwise.
func hasContivCustomIfAnnotation(annotations map[string]string) bool {
	for k := range annotations {
		if strings.HasPrefix(k, contivCustomIfAnnotation) {
			return true
		}
	}
	return false
}

// getContivCustomIfs returns alphabetically ordered slice of custom interfaces defined in pod annotations.
func getContivCustomIfs(annotations map[string]string) []string {
	out := make([]string, 0)

	for k, v := range annotations {
		if strings.HasPrefix(k, contivCustomIfAnnotation) {
			ifs := strings.Split(v, contivNamesSeparator)
			for _, i := range ifs {
				out = append(out, strings.TrimSpace(i))
			}
		}
	}
	sort.Strings(out)
	return out
}

// HasSaseServicesAnnotation returns true if provided annotations contain sase service annotation, false otherwise.
func HasSaseServicesAnnotation(annotations map[string]string) bool {
	for k := range annotations {
		if strings.HasPrefix(k, contivSaseServiceAnnotation) {
			return true
		}
	}
	return false
}

// GetSaseServices returns alphabetically ordered slice of sase services defined in pod annotations.
func GetSaseServices(annotations map[string]string) []string {
	out := make([]string, 0)

	for k, v := range annotations {
		if strings.HasPrefix(k, contivSaseServiceAnnotation) {
			ifs := strings.Split(v, contivNamesSeparator)
			for _, i := range ifs {
				out = append(out, strings.TrimSpace(i))
			}
		}
	}
	sort.Strings(out)
	return out
}

// ParseSaseServiceName parses Sase Service annotation into individual service name and instance
// eg. contivpp.io/sase-service: 1/sjc/firewall, 1/sjc/nat
// 	   contivpp.io/sase-service: 1/blr/routing, 1/blr/nat
func ParseSaseServiceName(ifAnnotation string) (serviceInfo PodSaseServiceInfo, err error) {
	ifParts := strings.Split(ifAnnotation, "/")
	if len(ifParts) < 2 {
		err = fmt.Errorf("invalid %s annotation value: %s", contivSaseServiceAnnotation, ifAnnotation)
		return
	}
	serviceInfo = PodSaseServiceInfo{
		serviceID:       ifParts[0],
		serviceLocation: ifParts[1],
		serviceType:     ifParts[2],
	}

	return
}