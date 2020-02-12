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

// FakeSiteResourceGroups implements SiteResourceGroupInterface
type FakeSiteResourceGroups struct {
	Fake *FakeContivppV1
	ns   string
}

var siteresourcegroupsResource = schema.GroupVersionResource{Group: "contivpp.io", Version: "v1", Resource: "siteresourcegroups"}

var siteresourcegroupsKind = schema.GroupVersionKind{Group: "contivpp.io", Version: "v1", Kind: "SiteResourceGroup"}

// Get takes name of the siteResourceGroup, and returns the corresponding siteResourceGroup object, and an error if there is any.
func (c *FakeSiteResourceGroups) Get(name string, options v1.GetOptions) (result *contivppiov1.SiteResourceGroup, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(siteresourcegroupsResource, c.ns, name), &contivppiov1.SiteResourceGroup{})

	if obj == nil {
		return nil, err
	}
	return obj.(*contivppiov1.SiteResourceGroup), err
}

// List takes label and field selectors, and returns the list of SiteResourceGroups that match those selectors.
func (c *FakeSiteResourceGroups) List(opts v1.ListOptions) (result *contivppiov1.SiteResourceGroupList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(siteresourcegroupsResource, siteresourcegroupsKind, c.ns, opts), &contivppiov1.SiteResourceGroupList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &contivppiov1.SiteResourceGroupList{ListMeta: obj.(*contivppiov1.SiteResourceGroupList).ListMeta}
	for _, item := range obj.(*contivppiov1.SiteResourceGroupList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested siteResourceGroups.
func (c *FakeSiteResourceGroups) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(siteresourcegroupsResource, c.ns, opts))

}

// Create takes the representation of a siteResourceGroup and creates it.  Returns the server's representation of the siteResourceGroup, and an error, if there is any.
func (c *FakeSiteResourceGroups) Create(siteResourceGroup *contivppiov1.SiteResourceGroup) (result *contivppiov1.SiteResourceGroup, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(siteresourcegroupsResource, c.ns, siteResourceGroup), &contivppiov1.SiteResourceGroup{})

	if obj == nil {
		return nil, err
	}
	return obj.(*contivppiov1.SiteResourceGroup), err
}

// Update takes the representation of a siteResourceGroup and updates it. Returns the server's representation of the siteResourceGroup, and an error, if there is any.
func (c *FakeSiteResourceGroups) Update(siteResourceGroup *contivppiov1.SiteResourceGroup) (result *contivppiov1.SiteResourceGroup, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(siteresourcegroupsResource, c.ns, siteResourceGroup), &contivppiov1.SiteResourceGroup{})

	if obj == nil {
		return nil, err
	}
	return obj.(*contivppiov1.SiteResourceGroup), err
}

// Delete takes name of the siteResourceGroup and deletes it. Returns an error if one occurs.
func (c *FakeSiteResourceGroups) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(siteresourcegroupsResource, c.ns, name), &contivppiov1.SiteResourceGroup{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeSiteResourceGroups) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(siteresourcegroupsResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &contivppiov1.SiteResourceGroupList{})
	return err
}

// Patch applies the patch and returns the patched siteResourceGroup.
func (c *FakeSiteResourceGroups) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *contivppiov1.SiteResourceGroup, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(siteresourcegroupsResource, c.ns, name, pt, data, subresources...), &contivppiov1.SiteResourceGroup{})

	if obj == nil {
		return nil, err
	}
	return obj.(*contivppiov1.SiteResourceGroup), err
}
