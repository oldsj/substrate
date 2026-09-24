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
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// resolveOwnerFixups returns non-root ownership records whose path is not
// shadowed by a later layer. Applying them to the mounted rootfs copies the
// changes into this bundle's upper, leaving the shared layer pool root-owned
// and removable by atelet.
func resolveOwnerFixups(layers []string) ([]ownedPath, error) {
	roots := make([]*os.Root, len(layers))
	metadata := make([]*whiteoutSet, len(layers))
	defer func() {
		for _, root := range roots {
			if root != nil {
				_ = root.Close()
			}
		}
	}()

	for i, layer := range layers {
		meta, err := readWhiteouts(layer)
		if err != nil {
			return nil, err
		}
		if meta.Version != whiteoutMetadataVersion {
			return nil, fmt.Errorf("layer %q has metadata version %d, want %d", layer, meta.Version, whiteoutMetadataVersion)
		}
		metadata[i] = meta
		root, err := os.OpenRoot(filepath.Join(layer, layerFSDirName))
		if err != nil {
			return nil, fmt.Errorf("while opening layer %q for owner resolution: %w", layer, err)
		}
		roots[i] = root
	}

	var fixups []ownedPath
	for i, meta := range metadata {
		for _, entry := range meta.Owners {
			if entry.UID == 0 && entry.GID == 0 {
				continue
			}
			rel, err := validateOwnedPath(entry.Path)
			if err != nil {
				return nil, fmt.Errorf("invalid ownership path in %q: %w", layers[i], err)
			}
			if rel == "." {
				continue // The merged root receives its metadata through upper/.
			}
			shadowed := false
			for j := i + 1; j < len(roots); j++ {
				_, blocked, err := lstatWithoutSymlinkParents(roots[j], rel)
				if blocked {
					shadowed = true
					break
				} else if err == nil {
					shadowed = true
					break
				} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOTDIR) {
					return nil, fmt.Errorf("while checking %q in layer %q: %w", rel, layers[j], err)
				}
			}
			if !shadowed {
				entry.Path = rel
				fixups = append(fixups, entry)
			}
		}
	}
	sortOwnedPaths(fixups)
	return fixups, nil
}

// applyOwnerFixups applies non-root ownership through the mounted rootfs.
// Overlayfs copies the changed metadata into the bundle-local upper instead
// of changing a layer shared by atelet's image cache.
func applyOwnerFixups(rootfsPath string, fixups []ownedPath) error {
	if len(fixups) == 0 {
		return nil
	}
	root, err := os.OpenRoot(rootfsPath)
	if err != nil {
		return fmt.Errorf("while opening rootfs %q: %w", rootfsPath, err)
	}
	defer root.Close()

	owners := append([]ownedPath(nil), fixups...)
	sortOwnedPaths(owners)
	for _, entry := range owners {
		if entry.UID == 0 && entry.GID == 0 {
			continue
		}
		rel, err := validateOwnedPath(entry.Path)
		if err != nil {
			return fmt.Errorf("invalid ownership path: %w", err)
		}
		if rel == "." {
			continue // The merged root receives its metadata through upper/.
		}
		fi, blocked, err := lstatWithoutSymlinkParents(root, rel)
		if blocked {
			continue
		}
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOTDIR) {
			// Whiteouts, opaque parents, and type changes can hide lower entries.
			continue
		} else if err != nil {
			return fmt.Errorf("while checking ownership path %q: %w", rel, err)
		}
		if err := lchownRoot(root, rel, entry.UID, entry.GID); err != nil {
			return fmt.Errorf("while restoring owner of %q: %w", rel, err)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			if err := root.Chmod(rel, fileModeFromTarBits(entry.Mode)); err != nil {
				return fmt.Errorf("while restoring mode of %q: %w", rel, err)
			}
		}
	}
	return nil
}

// lstatWithoutSymlinkParents checks each path component separately so a
// visible symlink or non-directory ancestor cannot redirect an ownership
// fixup to a different merged-view path.
func lstatWithoutSymlinkParents(root *os.Root, rel string) (os.FileInfo, bool, error) {
	parts := strings.Split(filepath.Clean(rel), string(filepath.Separator))
	current := "."
	for i, part := range parts {
		if current == "." {
			current = part
		} else {
			current = filepath.Join(current, part)
		}
		fi, err := root.Lstat(current)
		if err != nil {
			return nil, false, err
		}
		if i < len(parts)-1 && (fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir()) {
			return nil, true, nil
		}
		if i == len(parts)-1 {
			return fi, false, nil
		}
	}
	return nil, false, fmt.Errorf("invalid empty path %q", rel)
}

func sortOwnedPaths(owners []ownedPath) {
	sort.Slice(owners, func(i, j int) bool {
		depthI := strings.Count(owners[i].Path, string(filepath.Separator))
		depthJ := strings.Count(owners[j].Path, string(filepath.Separator))
		if owners[i].Path == "." {
			return false
		}
		if owners[j].Path == "." {
			return true
		}
		if depthI != depthJ {
			return depthI > depthJ
		}
		return owners[i].Path < owners[j].Path
	})
}

// lchownRoot changes ownership without following the final path component.
// Opening the parent with os.Root keeps intermediate symlink resolution
// confined to the supplied tree.
func lchownRoot(root *os.Root, rel string, uid, gid int) error {
	if rel == "." {
		f, err := root.Open(".")
		if err != nil {
			return err
		}
		defer f.Close()
		return unix.Fchown(int(f.Fd()), uid, gid)
	}
	parent, err := root.OpenRoot(filepath.Dir(rel))
	if err != nil {
		return err
	}
	defer parent.Close()
	dir, err := parent.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return unix.Fchownat(int(dir.Fd()), filepath.Base(rel), uid, gid, unix.AT_SYMLINK_NOFOLLOW)
}
