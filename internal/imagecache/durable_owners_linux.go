//go:build linux

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

package imagecache

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/agent-substrate/substrate/internal/ateompath"
	"golang.org/x/sys/unix"
)

// ApplyInitialDurableDirOwners applies the owner assignments in each bundle's
// overlay spec, in container spec order. It is called only for a fresh run,
// before any workload container starts. Restores must use the owner metadata
// carried by the durable-volume tar instead.
func ApplyInitialDurableDirOwners(actorUID string, containerNames []string) error {
	for _, containerName := range containerNames {
		bundlePath := ateompath.OCIBundlePath(actorUID, containerName)
		spec, err := ReadSpec(bundlePath)
		if err != nil {
			return fmt.Errorf("while reading durable-dir owners from bundle %q: %w", bundlePath, err)
		}
		if spec == nil {
			continue
		}
		for _, owner := range spec.DurableDirOwners {
			if owner.UID == 0 {
				continue
			}
			if owner.Name == "" || owner.Name == "." || filepath.Base(owner.Name) != owner.Name || !filepath.IsLocal(owner.Name) {
				return fmt.Errorf("invalid durable-dir volume name %q in bundle %q", owner.Name, bundlePath)
			}
			volumePath := filepath.Join(ateompath.DurableDirVolumeMountsDir(actorUID), owner.Name)
			if err := applyInitialDurableDirOwner(volumePath, owner); err != nil {
				return fmt.Errorf("while initializing durable-dir volume %q for container %q: %w", owner.Name, containerName, err)
			}
		}
	}
	return nil
}

// applyInitialDurableDirOwner changes only a still-root-owned, empty directory.
// Opening with O_NOFOLLOW and changing ownership through the file descriptor
// keeps a replaced symlink from redirecting the privileged chown.
func applyInitialDurableDirOwner(path string, owner DurableDirOwner) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("opening volume directory: %w", err)
	}
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stating volume directory: %w", err)
	}
	if stat.Uid != 0 || stat.Gid != 0 {
		return nil
	}

	entries, err := dir.ReadDir(1)
	if len(entries) != 0 {
		return nil
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("checking whether volume directory is empty: %w", err)
	}

	if err := unix.Fchown(fd, int(owner.UID), int(owner.GID)); err != nil {
		return fmt.Errorf("changing volume directory owner: %w", err)
	}
	return nil
}
