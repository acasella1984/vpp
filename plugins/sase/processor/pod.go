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

package processor

import (
	"sort"
	"strings"
)

const (
	contivAnnotationPrefix            = "contivpp.io/"
	contivMicroserviceLabelAnnotation = contivAnnotationPrefix + "microservice-label"  // k8s annotation used to specify microservice label of a pod
	contivServiceEndpointIfAnnotation = contivAnnotationPrefix + "service-endpoint-if" // k8s annotation used to specify k8s service endpoint interface
	contivCustomIfAnnotation          = contivAnnotationPrefix + "custom-if"           // k8s annotation used to request custom pod interfaces
	contivCustomIfSeparator           = ","                                            // separator used to split multiple interfaces in k8s annotation

	memifIfType = "memif"
	tapIfType   = "tap"
	vethIfType  = "veth"
)

// getContivMicroserviceLabel returns microservice label defined in pod annotations
// (or an empty string if it is not defined).
func getContivMicroserviceLabel(annotations map[string]string) string {
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
			ifs := strings.Split(v, contivCustomIfSeparator)
			for _, i := range ifs {
				out = append(out, strings.TrimSpace(i))
			}
		}
	}
	sort.Strings(out)
	return out
}
