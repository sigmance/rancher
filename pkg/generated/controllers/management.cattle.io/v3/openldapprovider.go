/*
Copyright 2025 Rancher Labs, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by main. DO NOT EDIT.

package v3

import (
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generic"
)

// OpenLdapProviderController interface for managing OpenLdapProvider resources.
type OpenLdapProviderController interface {
	generic.NonNamespacedControllerInterface[*v3.OpenLdapProvider, *v3.OpenLdapProviderList]
}

// OpenLdapProviderClient interface for managing OpenLdapProvider resources in Kubernetes.
type OpenLdapProviderClient interface {
	generic.NonNamespacedClientInterface[*v3.OpenLdapProvider, *v3.OpenLdapProviderList]
}

// OpenLdapProviderCache interface for retrieving OpenLdapProvider resources in memory.
type OpenLdapProviderCache interface {
	generic.NonNamespacedCacheInterface[*v3.OpenLdapProvider]
}
