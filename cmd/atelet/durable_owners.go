// Copyright 2026 Google LLC
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

package main

import (
	"fmt"

	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/imagecache"
	"github.com/agent-substrate/substrate/internal/ocispec"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
)

// selectDurableDirOwners assigns each durable volume to the first container
// with a non-root process that mounts it. Durable-dir mounts are always rw;
// container order is the order in the workload spec.
func selectDurableDirOwners(
	volumes []*ateletpb.Volume,
	containers []*ateletpb.Container,
	users map[string]processUser,
) map[string][]imagecache.DurableDirOwner {
	durable := make(map[string]bool, len(volumes))
	for _, volume := range volumes {
		if _, ok := volume.GetSource().(*ateletpb.Volume_DurableDir); ok {
			durable[volume.GetName()] = true
		}
	}

	claimed := make(map[string]bool, len(durable))
	ownersByContainer := make(map[string][]imagecache.DurableDirOwner)
	for _, container := range containers {
		user, ok := users[container.GetName()]
		if !ok || user.UID == 0 {
			continue
		}
		for _, mount := range container.GetVolumeMounts() {
			name := mount.GetName()
			if !durable[name] || claimed[name] {
				continue
			}
			ownersByContainer[container.GetName()] = append(
				ownersByContainer[container.GetName()],
				imagecache.DurableDirOwner{Name: name, UID: user.UID, GID: user.GID},
			)
			claimed[name] = true
		}
	}
	return ownersByContainer
}

// writeDurableDirOwners records the fresh-volume assignments in the selected
// containers' overlay specs after all OCI specs have their resolved image users.
func writeDurableDirOwners(actorUID string, volumes []*ateletpb.Volume, containers []*ateletpb.Container) error {
	users := make(map[string]processUser, len(containers))
	for _, container := range containers {
		bundlePath := ateompath.OCIBundlePath(actorUID, container.GetName())
		spec, err := ocispec.Load(bundlePath)
		if err != nil {
			return fmt.Errorf("while reading OCI spec for container %q: %w", container.GetName(), err)
		}
		if spec.Process == nil {
			return fmt.Errorf("OCI spec for container %q has no process", container.GetName())
		}
		users[container.GetName()] = processUser{UID: spec.Process.User.UID, GID: spec.Process.User.GID}
	}

	ownersByContainer := selectDurableDirOwners(volumes, containers, users)
	for _, container := range containers {
		owners := ownersByContainer[container.GetName()]
		if len(owners) == 0 {
			continue
		}
		bundlePath := ateompath.OCIBundlePath(actorUID, container.GetName())
		spec, err := imagecache.ReadSpec(bundlePath)
		if err != nil {
			return fmt.Errorf("while reading overlay spec for container %q: %w", container.GetName(), err)
		}
		if spec == nil {
			return fmt.Errorf("container %q has no overlay spec for durable-dir ownership", container.GetName())
		}
		spec.DurableDirOwners = owners
		if err := imagecache.WriteSpec(bundlePath, spec); err != nil {
			return fmt.Errorf("while writing durable-dir owners for container %q: %w", container.GetName(), err)
		}
	}
	return nil
}
