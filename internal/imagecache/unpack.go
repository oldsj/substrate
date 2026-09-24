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
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	whiteoutMetadataVersion = 2

	// whiteoutPrefix marks an OCI layer entry that deletes the same-named
	// path from lower layers.
	whiteoutPrefix = ".wh."
	// opaqueMarkerName marks its directory as opaque: lower-layer contents of
	// that directory are hidden entirely.
	opaqueMarkerName = ".wh..wh..opq"
)

// whiteoutSet records per-layer metadata captured at unpack time that the
// (privileged) consumer needs at compose time: whiteout state materialized by
// FinalizeLayer, implicit directories, and non-root ownership entries.
// Paths are clean and relative to the layer's fs/ root.
type whiteoutSet struct {
	Version int `json:"version"`
	// Whiteouts are paths that must become 0:0 char devices in the lowerdir.
	Whiteouts []string `json:"whiteouts,omitempty"`
	// Opaques are directories that must carry trusted.overlay.opaque=y.
	Opaques []string `json:"opaques,omitempty"`
	// ImplicitDirs are directories the layer tar never declared but that
	// exist in the tree because a child entry (or a whiteout materialized at
	// finalize) needed a parent. Their root:root 0755 attrs are fabricated;
	// in the composed overlay the top-most layer containing a directory
	// supplies its metadata, so an implicit dir here would shadow the real
	// attrs a lower layer declared (e.g. /tmp's 1777). SetupBundleRootfs
	// repairs the merged view from these records (see resolveImplicitDirFixups).
	ImplicitDirs []string `json:"implicitDirs,omitempty"`
	// Owners records non-root owners that atelet cannot apply without
	// CAP_CHOWN. SetupBundleRootfs applies them through the bundle overlay,
	// keeping the shared cached layer tree root-owned.
	Owners []ownedPath `json:"owners,omitempty"`
}

// ownedPath is a path whose image owner is not root. Mode uses Unix's 0o7777
// permission and special-bit representation so the overlay copy-up can restore
// it after chown clears setuid/setgid bits.
type ownedPath struct {
	Path string `json:"path"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
	Mode uint32 `json:"mode"`
}

func tarModeBits(mode os.FileMode) uint32 {
	bits := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if mode&os.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if mode&os.ModeSticky != 0 {
		bits |= 0o1000
	}
	return bits
}

func fileModeFromTarBits(bits uint32) os.FileMode {
	mode := os.FileMode(bits & 0o777)
	if bits&0o4000 != 0 {
		mode |= os.ModeSetuid
	}
	if bits&0o2000 != 0 {
		mode |= os.ModeSetgid
	}
	if bits&0o1000 != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

func readWhiteouts(layerDir string) (*whiteoutSet, error) {
	b, err := os.ReadFile(filepath.Join(layerDir, layerWhiteoutsFileName))
	if errors.Is(err, os.ErrNotExist) {
		return &whiteoutSet{}, nil
	} else if err != nil {
		return nil, fmt.Errorf("while reading layer whiteouts: %w", err)
	}
	var wh whiteoutSet
	if err := json.Unmarshal(b, &wh); err != nil {
		return nil, fmt.Errorf("while decoding layer whiteouts: %w", err)
	}
	return &wh, nil
}

func validateTarName(name string) (cleaned string, skip bool, err error) {
	if name == "" {
		return "", true, nil
	}
	cleaned = filepath.Clean(name)
	if cleaned == "." {
		return "", true, nil
	}
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "" || cleaned == "." {
		return "", true, nil
	}
	if !filepath.IsLocal(cleaned) {
		return "", false, fmt.Errorf("not a local path: %q", name)
	}
	return cleaned, false, nil
}

func validateOwnedPath(name string) (string, error) {
	if name == "." {
		return name, nil
	}
	rel, skip, err := validateTarName(name)
	if err != nil {
		return "", err
	}
	if skip {
		return "", fmt.Errorf("empty path")
	}
	return rel, nil
}

// unpackLayer extracts one uncompressed OCI layer tar into root. Whiteout
// entries (.wh.*) are not written to the tree; they are returned so the
// caller can persist them for later materialization by a privileged process.
//
// Unlike a flattened-image extract, cross-layer "later entry wins" semantics
// are overlayfs's job now; the handling here only needs to cope with
// duplicate entries within a single layer (real ko images repeat directory
// entries).
func unpackLayer(ctx context.Context, tarData io.Reader, root *os.Root) (*whiteoutSet, error) {
	wh := &whiteoutSet{Version: whiteoutMetadataVersion}

	// Directories are created owner-writable during extraction (so their children
	// can be written even when the image marks them read-only, e.g. ko ships
	// /ko-app as 0555) and their real modes are restored afterwards. This lets
	// atelet, running as plain root, unpack arbitrary actor images without
	// CAP_DAC_OVERRIDE. Keyed by name so a repeated dir entry's last mode wins.
	dirModes := map[string]os.FileMode{}

	// Ancestors an entry needed vs. directories the tar declared: the
	// difference is recorded as ImplicitDirs (attrs fabricated, see the
	// whiteoutSet field doc). Whiteout/opaque markers count too — their
	// parents are created by FinalizeLayer's MkdirAll with the same
	// fabricated attrs.
	declared := map[string]bool{}
	implicit := map[string]bool{}
	owners := map[string]ownedPath{}
	setOwner := func(name string, uid, gid int, mode os.FileMode) {
		if uid == 0 && gid == 0 {
			delete(owners, name)
			return
		}
		owners[name] = ownedPath{Path: name, UID: uid, GID: gid, Mode: tarModeBits(mode)}
	}
	clearOwners := func(name string) {
		for p := range owners {
			if p == name || strings.HasPrefix(p, name+string(filepath.Separator)) {
				delete(owners, p)
			}
		}
	}
	markAncestors := func(name string) {
		for p := filepath.Dir(name); p != "."; p = filepath.Dir(p) {
			if !declared[p] {
				implicit[p] = true
			}
		}
	}

	tarReader := tar.NewReader(tarData)
	for {
		hdr, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("in tarReader.Next: %w", err)
		}

		name, skip, err := validateTarName(hdr.Name)
		if err != nil {
			return nil, fmt.Errorf("invalid tar entry: %w", err)
		}
		if skip {
			// A tar can declare metadata for the layer root as ".". The fs/
			// directory is created by atelet, so retain non-root ownership in
			// metadata for SetupBundleRootfs to apply to the bundle's upper.
			if hdr.Typeflag == tar.TypeDir && isRootTarName(hdr.Name) {
				mode := hdr.FileInfo().Mode()
				dirModes["."] = fileModeFromTarBits(tarModeBits(mode))
				declared["."] = true
				delete(implicit, ".")
				setOwner(".", hdr.Uid, hdr.Gid, mode)
			}
			continue
		}

		if base := filepath.Base(name); base == opaqueMarkerName {
			if dir := filepath.Dir(name); dir != "." {
				wh.Opaques = append(wh.Opaques, dir)
			}
			markAncestors(name)
			continue
		} else if strings.HasPrefix(base, whiteoutPrefix+whiteoutPrefix) {
			// AUFS bookkeeping entries (.wh..wh.plnk, .wh..wh.aufs, ...);
			// nothing to represent in an overlayfs lowerdir.
			continue
		} else if deleted, ok := strings.CutPrefix(base, whiteoutPrefix); ok {
			wh.Whiteouts = append(wh.Whiteouts, filepath.Join(filepath.Dir(name), deleted))
			markAncestors(name)
			continue
		}

		mode := hdr.FileInfo().Mode()

		// A layer tar routinely omits entries for parent directories that
		// exist in lower layers (e.g. just "etc/nsswitch.conf", with "etc/"
		// declared only in the base layer). Unpacking per layer, those
		// parents must be created here; overlayfs merges them with the
		// lower layers' directories at compose time.
		markAncestors(name)
		if parent := filepath.Dir(name); parent != "." {
			if err := root.MkdirAll(parent, 0o755); err != nil {
				return nil, fmt.Errorf("while creating parent directories for %q: %w", name, err)
			}
		}

		switch hdr.Typeflag {
		case tar.TypeReg: // Regular file
			// "Later entry wins" within the layer: if any entry exists at the target
			// path, remove it first. This ensures that:
			// 1. If it's a symlink, we don't write through it (security vulnerability / incorrectness).
			// 2. If it's a hardlink, we unlink it instead of truncating the shared inode.
			// 3. If it's a directory, we recursively remove it so we can write the file.
			if _, err := root.Lstat(name); err == nil {
				if err := root.RemoveAll(name); err != nil {
					return nil, fmt.Errorf("while replacing existing path at %q before regular file: %w", name, err)
				}
				clearOwners(name)
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("while checking existing path at %q before regular file: %w", name, err)
			}

			// Stream directly from tarReader to target file to avoid buffering in memory.
			outFile, err := root.OpenFile(name, os.O_CREATE|os.O_RDWR|os.O_TRUNC, mode.Perm())
			if err != nil {
				return nil, fmt.Errorf("while creating file %q: %w", name, err)
			}

			_, err = io.Copy(outFile, tarReader)
			closeErr := outFile.Close()

			if err != nil {
				return nil, fmt.Errorf("while writing contents of %q from tar stream: %w", name, err)
			}
			if closeErr != nil {
				return nil, fmt.Errorf("while closing file %q: %w", name, closeErr)
			}
			setOwner(name, hdr.Uid, hdr.Gid, mode)

		case tar.TypeDir:
			// Create owner-writable so children can be written even when the image
			// marks the dir read-only; the real mode is restored after extraction
			// (see dirModes / the restore pass below).
			err := root.Mkdir(name, mode.Perm()|0o700)
			if errors.Is(err, os.ErrExist) {
				// OCI layers can repeat a directory entry (real ko images do); the
				// existing dir is already owner-writable, so let the later entry's
				// mode win at restore time.
			} else if err != nil {
				return nil, fmt.Errorf("while creating directory=%q, mode=%v: %w", name, mode, err)
			}
			dirModes[name] = fileModeFromTarBits(tarModeBits(mode))
			declared[name] = true
			delete(implicit, name)
			setOwner(name, hdr.Uid, hdr.Gid, mode)

		case tar.TypeSymlink:
			// A layer may re-define the same path (e.g. declare /var/run as a dir
			// then re-declare it as a symlink). Standard tar-extract semantics are
			// "later entry wins": replace any existing entry.
			if existing, err := root.Lstat(name); err == nil {
				// If it's already the same symlink, skip the unlink+symlink pair.
				if existing.Mode()&os.ModeSymlink != 0 {
					if cur, rerr := root.Readlink(name); rerr == nil && cur == hdr.Linkname {
						setOwner(name, hdr.Uid, hdr.Gid, mode)
						continue
					}
				}
				// Root.RemoveAll removes the symlink entry itself; it does NOT
				// traverse and remove the directory the symlink points to.
				// That's the desired semantic here — replace this path's
				// entry without touching whatever the prior symlink targeted.
				if err := root.RemoveAll(name); err != nil {
					return nil, fmt.Errorf("while replacing existing path at %q before symlink: %w", name, err)
				}
				clearOwners(name)
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("while checking existing path at %q before symlink: %w", name, err)
			}
			if err := root.Symlink(hdr.Linkname, name); err != nil {
				return nil, fmt.Errorf("while creating symlink src=%q target=%q: %w", name, hdr.Linkname, err)
			}
			setOwner(name, hdr.Uid, hdr.Gid, mode)

		case tar.TypeLink:
			linkname, linkSkip, err := validateTarName(hdr.Linkname)
			if err != nil {
				return nil, fmt.Errorf("invalid hardlink target for %q: %w", name, err)
			}
			if linkSkip {
				return nil, fmt.Errorf("invalid hardlink target for %q: empty", name)
			}
			// Same "later entry wins" handling as TypeSymlink: replace existing entry.
			if _, err := root.Lstat(name); err == nil {
				if err := root.RemoveAll(name); err != nil {
					return nil, fmt.Errorf("while replacing existing path at %q before hardlink: %w", name, err)
				}
				clearOwners(name)
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("while checking existing path at %q before hardlink: %w", name, err)
			}
			if err := root.Link(linkname, name); err != nil {
				return nil, fmt.Errorf("while creating hardlink src=%q target=%q: %w", name, linkname, err)
			}
			fi, err := root.Lstat(name)
			if err != nil {
				return nil, fmt.Errorf("while statting hardlink %q: %w", name, err)
			}
			setOwner(name, hdr.Uid, hdr.Gid, fi.Mode())

		default:
			tfStr := string([]byte{hdr.Typeflag})
			slog.ErrorContext(ctx, "Unhandled tar entry typeflag", slog.String("typeflag", tfStr), slog.Any("hdr", hdr))
			return nil, fmt.Errorf("unhandled tar entry typeflag %q", tfStr)
		}
	}

	// Restore the image's intended directory modes now that every child exists.
	// Deepest paths first: a child's path is always longer than its parent's, so
	// length-descending order guarantees a directory is restored before any of its
	// ancestors — restoring a parent to a non-traversable mode then can't block
	// restoring its children.
	dirs := make([]string, 0, len(dirModes))
	for name := range dirModes {
		dirs = append(dirs, name)
	}
	sort.Slice(dirs, func(i, j int) bool {
		if dirs[i] == "." {
			return false
		}
		if dirs[j] == "." {
			return true
		}
		return len(dirs[i]) > len(dirs[j])
	})
	for _, name := range dirs {
		if err := root.Chmod(name, dirModes[name]); err != nil {
			return nil, fmt.Errorf("while restoring mode %v on directory %q: %w", dirModes[name], name, err)
		}
	}

	// Keep only implicit candidates that survive in the tree as directories
	// ("later entry wins" may have replaced one with a file or symlink), plus
	// the ones FinalizeLayer will create for whiteout/opaque materialization
	// (they may not exist yet). Sorted for deterministic metadata.
	finalizeDirs := map[string]bool{}
	for _, w := range wh.Whiteouts {
		for p := filepath.Dir(w); p != "."; p = filepath.Dir(p) {
			finalizeDirs[p] = true
		}
	}
	for _, o := range wh.Opaques {
		for p := o; p != "."; p = filepath.Dir(p) {
			finalizeDirs[p] = true
		}
	}
	for p := range implicit {
		if declared[p] {
			continue
		}
		if fi, err := root.Lstat(p); err == nil && fi.IsDir() {
			wh.ImplicitDirs = append(wh.ImplicitDirs, p)
		} else if finalizeDirs[p] {
			wh.ImplicitDirs = append(wh.ImplicitDirs, p)
		}
	}
	sort.Strings(wh.ImplicitDirs)
	ownerNames := make([]string, 0, len(owners))
	for name := range owners {
		ownerNames = append(ownerNames, name)
	}
	sort.Strings(ownerNames)
	for _, name := range ownerNames {
		wh.Owners = append(wh.Owners, owners[name])
	}

	return wh, nil
}

func isRootTarName(name string) bool {
	return name != "" && filepath.Clean(strings.TrimPrefix(name, "/")) == "."
}
