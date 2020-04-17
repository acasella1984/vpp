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

package externalversions

import (
	"fmt"

	v1 "github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
	nodeconfigv1 "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	telemetryv1 "github.com/contiv/vpp/plugins/crd/pkg/apis/telemetry/v1"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	cache "k8s.io/client-go/tools/cache"
)

// GenericInformer is type of SharedIndexInformer which will locate and delegate to other
// sharedInformers based on type
type GenericInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() cache.GenericLister
}

type genericInformer struct {
	informer cache.SharedIndexInformer
	resource schema.GroupResource
}

// Informer returns the SharedIndexInformer.
func (f *genericInformer) Informer() cache.SharedIndexInformer {
	return f.informer
}

// Lister returns the GenericLister.
func (f *genericInformer) Lister() cache.GenericLister {
	return cache.NewGenericLister(f.Informer().GetIndexer(), f.resource)
}

// ForResource gives generic access to a shared informer of the matching type
// TODO extend this to unknown resources with a client pool
func (f *sharedInformerFactory) ForResource(resource schema.GroupVersionResource) (GenericInformer, error) {
	switch resource {
	// Group=contivpp.io, Version=v1
	case v1.SchemeGroupVersion.WithResource("customconfigurations"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Contivpp().V1().CustomConfigurations().Informer()}, nil
	case v1.SchemeGroupVersion.WithResource("customnetworks"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Contivpp().V1().CustomNetworks().Informer()}, nil
	case v1.SchemeGroupVersion.WithResource("externalinterfaces"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Contivpp().V1().ExternalInterfaces().Informer()}, nil
	case v1.SchemeGroupVersion.WithResource("ipsecvpntunnels"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Contivpp().V1().IPSecVpnTunnels().Informer()}, nil
	case v1.SchemeGroupVersion.WithResource("networkfirewallprofiles"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Contivpp().V1().NetworkFirewallProfiles().Informer()}, nil
	case v1.SchemeGroupVersion.WithResource("saseservicepolicies"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Contivpp().V1().SaseServicePolicies().Informer()}, nil
	case v1.SchemeGroupVersion.WithResource("securityassociations"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Contivpp().V1().SecurityAssociations().Informer()}, nil
	case v1.SchemeGroupVersion.WithResource("servicefunctionchains"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Contivpp().V1().ServiceFunctionChains().Informer()}, nil
	case v1.SchemeGroupVersion.WithResource("serviceroutes"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Contivpp().V1().ServiceRoutes().Informer()}, nil
	case v1.SchemeGroupVersion.WithResource("siteresourcegroups"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Contivpp().V1().SiteResourceGroups().Informer()}, nil

		// Group=nodeconfig.contiv.vpp, Version=v1
	case nodeconfigv1.SchemeGroupVersion.WithResource("nodeconfigs"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Nodeconfig().V1().NodeConfigs().Informer()}, nil

		// Group=telemetry.contiv.vpp, Version=v1
	case telemetryv1.SchemeGroupVersion.WithResource("telemetryreports"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Telemetry().V1().TelemetryReports().Informer()}, nil

	}

	return nil, fmt.Errorf("no informer found for %v", resource)
}
