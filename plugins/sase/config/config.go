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

package config

const (
	// by default traffic is equally distributed between local and remote backends
	defaultServiceLocalEndpointWeight = 1
)

// Config holds default values for sase services
type Config struct {
}

// DefaultNatConfig returns configuration for service plugin with default values.
func DefaultNatConfig() *Config {
	return &Config{}
}

// DefaultFirewallConfig returns configuration for service plugin with default values.
func DefaultFirewallConfig() *Config {
	return &Config{}
}

// DefaultIPSecConfig returns configuration for service plugin with default values.
func DefaultIPSecConfig() *Config {
	return &Config{}
}

// DefaultRouteConfig returns configuration for service plugin with default values.
func DefaultRouteConfig() *Config {
	return &Config{}
}
