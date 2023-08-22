// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

// DefaultStorageListener default storage listener implementation
type DefaultStorageListener struct{}

// OnAPIKeysUpdated notifies api keys have been updated
func (d *DefaultStorageListener) OnAPIKeysUpdated() {}

// OnAuthTypesUpdated notifies auth types have been updated
func (d *DefaultStorageListener) OnAuthTypesUpdated() {}

// OnIdentityProvidersUpdated notifies identity providers have been updated
func (d *DefaultStorageListener) OnIdentityProvidersUpdated() {}

// OnServiceRegistrationsUpdated notifies services regs have been updated
func (d *DefaultStorageListener) OnServiceRegistrationsUpdated() {}

// OnOrganizationsUpdated notifies organizations have been updated
func (d *DefaultStorageListener) OnOrganizationsUpdated() {}

// OnApplicationsUpdated notifies applications have been updated
func (d *DefaultStorageListener) OnApplicationsUpdated() {}

// OnApplicationsOrganizationsUpdated notifies applications organizations have been updated
func (d *DefaultStorageListener) OnApplicationsOrganizationsUpdated() {}

// OnApplicationConfigsUpdated notifies application configs have been updated
func (d *DefaultStorageListener) OnApplicationConfigsUpdated() {}

// OnConfigsUpdated notifies configs have been updated
func (d *DefaultStorageListener) OnConfigsUpdated() {}
