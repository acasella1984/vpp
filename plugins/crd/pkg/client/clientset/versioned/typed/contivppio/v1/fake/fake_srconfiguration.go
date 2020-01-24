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

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	contivppiov1 "github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeSrConfigurations implements SrConfigurationInterface
type FakeSrConfigurations struct {
	Fake *FakeContivppV1
	ns   string
}

var srconfigurationsResource = schema.GroupVersionResource{Group: "contivpp.io", Version: "v1", Resource: "srconfigurations"}

var srconfigurationsKind = schema.GroupVersionKind{Group: "contivpp.io", Version: "v1", Kind: "SrConfiguration"}

// Get takes name of the srConfiguration, and returns the corresponding srConfiguration object, and an error if there is any.
func (c *FakeSrConfigurations) Get(name string, options v1.GetOptions) (result *contivppiov1.SrConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(srconfigurationsResource, c.ns, name), &contivppiov1.SrConfiguration{})

	if obj == nil {
		return nil, err
	}
	return obj.(*contivppiov1.SrConfiguration), err
}

// List takes label and field selectors, and returns the list of SrConfigurations that match those selectors.
func (c *FakeSrConfigurations) List(opts v1.ListOptions) (result *contivppiov1.SrConfigurationList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(srconfigurationsResource, srconfigurationsKind, c.ns, opts), &contivppiov1.SrConfigurationList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &contivppiov1.SrConfigurationList{ListMeta: obj.(*contivppiov1.SrConfigurationList).ListMeta}
	for _, item := range obj.(*contivppiov1.SrConfigurationList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested srConfigurations.
func (c *FakeSrConfigurations) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(srconfigurationsResource, c.ns, opts))

}

// Create takes the representation of a srConfiguration and creates it.  Returns the server's representation of the srConfiguration, and an error, if there is any.
func (c *FakeSrConfigurations) Create(srConfiguration *contivppiov1.SrConfiguration) (result *contivppiov1.SrConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(srconfigurationsResource, c.ns, srConfiguration), &contivppiov1.SrConfiguration{})

	if obj == nil {
		return nil, err
	}
	return obj.(*contivppiov1.SrConfiguration), err
}

// Update takes the representation of a srConfiguration and updates it. Returns the server's representation of the srConfiguration, and an error, if there is any.
func (c *FakeSrConfigurations) Update(srConfiguration *contivppiov1.SrConfiguration) (result *contivppiov1.SrConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(srconfigurationsResource, c.ns, srConfiguration), &contivppiov1.SrConfiguration{})

	if obj == nil {
		return nil, err
	}
	return obj.(*contivppiov1.SrConfiguration), err
}

// Delete takes name of the srConfiguration and deletes it. Returns an error if one occurs.
func (c *FakeSrConfigurations) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(srconfigurationsResource, c.ns, name), &contivppiov1.SrConfiguration{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeSrConfigurations) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(srconfigurationsResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &contivppiov1.SrConfigurationList{})
	return err
}

// Patch applies the patch and returns the patched srConfiguration.
func (c *FakeSrConfigurations) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *contivppiov1.SrConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(srconfigurationsResource, c.ns, name, pt, data, subresources...), &contivppiov1.SrConfiguration{})

	if obj == nil {
		return nil, err
	}
	return obj.(*contivppiov1.SrConfiguration), err
}
