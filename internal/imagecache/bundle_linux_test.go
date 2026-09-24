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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/agent-substrate/substrate/internal/roottest"
)

// writeLayer builds a layer dir (fs/ tree + whiteouts.json) as the store's
// unpack would.
func writeLayer(t *testing.T, dir string, files map[string]string, wh *whiteoutSet) {
	t.Helper()
	fs := filepath.Join(dir, layerFSDirName)
	if err := os.MkdirAll(fs, 0o755); err != nil {
		t.Fatalf("mkdir fs: %v", err)
	}
	for name, body := range files {
		p := filepath.Join(fs, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if wh == nil {
		wh = &whiteoutSet{}
	}
	wh.Version = whiteoutMetadataVersion
	b, err := json.Marshal(wh)
	if err != nil {
		t.Fatalf("marshal whiteouts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, layerWhiteoutsFileName), b, 0o600); err != nil {
		t.Fatalf("write whiteouts.json: %v", err)
	}
}

// FinalizeLayer materializes whiteout devices (mknod, CAP_MKNOD) and opaque
// xattrs (trusted.*, CAP_SYS_ADMIN); only root has those in a plain test
// environment. Runs in privileged CI / root shells, skips elsewhere.
func TestFinalizeLayer_MaterializesWhiteouts(t *testing.T) {
	roottest.Require(t, "CAP_MKNOD + CAP_SYS_ADMIN for trusted.* xattrs")
	dir := t.TempDir()
	writeLayer(t, dir,
		map[string]string{"kept.txt": "kept"},
		&whiteoutSet{
			Whiteouts: []string{"removed.txt", "sub/dir/removed-deep.txt"},
			Opaques:   []string{"opaque-dir"},
		})

	if err := FinalizeLayer(dir); err != nil {
		t.Fatalf("FinalizeLayer: %v", err)
	}

	for _, p := range []string{"removed.txt", "sub/dir/removed-deep.txt"} {
		fi, err := os.Lstat(filepath.Join(dir, layerFSDirName, p))
		if err != nil {
			t.Fatalf("whiteout %q not created: %v", p, err)
		}
		if fi.Mode()&os.ModeCharDevice == 0 {
			t.Errorf("whiteout %q mode = %v, want char device", p, fi.Mode())
		}
		var st unix.Stat_t
		if err := unix.Stat(filepath.Join(dir, layerFSDirName, p), &st); err == nil && st.Rdev != 0 {
			t.Errorf("whiteout %q rdev = %d, want 0:0", p, st.Rdev)
		}
	}

	var val [8]byte
	n, err := unix.Getxattr(filepath.Join(dir, layerFSDirName, "opaque-dir"), "trusted.overlay.opaque", val[:])
	if err != nil || string(val[:n]) != "y" {
		t.Errorf("opaque xattr = %q (err=%v), want \"y\"", val[:n], err)
	}

	if _, err := os.Stat(filepath.Join(dir, layerFinalizedMarkerName)); err != nil {
		t.Errorf("finalized marker missing: %v", err)
	}

	// Idempotent: second call is a marker-hit no-op.
	if err := FinalizeLayer(dir); err != nil {
		t.Errorf("FinalizeLayer (second call): %v", err)
	}
}

// Escape rejection needs no privileges: a crafted whiteouts.json must fail
// validation before any mknod/setxattr is attempted.
func TestFinalizeLayer_RejectsEscapingPaths(t *testing.T) {
	t.Run("whiteout escape", func(t *testing.T) {
		dir := t.TempDir()
		writeLayer(t, dir, nil, &whiteoutSet{Whiteouts: []string{"../escape"}})
		if err := FinalizeLayer(dir); err == nil {
			t.Errorf("FinalizeLayer accepted an escaping whiteout path")
		}
	})
	t.Run("opaque escape", func(t *testing.T) {
		dir := t.TempDir()
		writeLayer(t, dir, nil, &whiteoutSet{Opaques: []string{"a/../../escape"}})
		if err := FinalizeLayer(dir); err == nil {
			t.Errorf("FinalizeLayer accepted an escaping opaque path")
		}
	})
	t.Run("owner escape", func(t *testing.T) {
		dir := t.TempDir()
		writeLayer(t, dir, nil, &whiteoutSet{Owners: []ownedPath{{Path: "../escape", UID: 10001, GID: 10002}}})
		if err := FinalizeLayer(dir); err == nil {
			t.Errorf("FinalizeLayer accepted an escaping ownership path")
		}
	})
}

// A layer with no whiteouts.json finalizes to just the marker; needs no
// privileges.
func TestFinalizeLayer_NoWhiteouts(t *testing.T) {
	dir := t.TempDir()
	writeLayer(t, dir, map[string]string{"f": "x"}, nil)
	if err := FinalizeLayer(dir); err != nil {
		t.Fatalf("FinalizeLayer: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, layerFinalizedMarkerName)); err != nil {
		t.Errorf("finalized marker missing: %v", err)
	}
}

func TestFinalizeLayer_RejectsMissingOwnershipMetadata(t *testing.T) {
	for _, tc := range []struct {
		name      string
		metadata  []byte
		finalized bool
	}{
		{name: "missing metadata", metadata: nil},
		{name: "legacy metadata with finalized marker", metadata: []byte(`{"version":1}`), finalized: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, layerFSDirName), 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.metadata != nil {
				if err := os.WriteFile(filepath.Join(dir, layerWhiteoutsFileName), tc.metadata, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.finalized {
				if err := os.WriteFile(filepath.Join(dir, layerFinalizedMarkerName), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := FinalizeLayer(dir)
			if err == nil || !strings.Contains(err.Error(), "metadata version") {
				t.Fatalf("FinalizeLayer error = %v, want metadata-version error", err)
			}
		})
	}
}

func TestResolveOwnerFixups_OnlyNonRootVisibleEntries(t *testing.T) {
	lower := t.TempDir()
	writeLayer(t, lower, map[string]string{"owned": "owned", "shadowed": "lower", "root-owned": "root"}, &whiteoutSet{Owners: []ownedPath{
		{Path: ".", UID: 10005, GID: 10006, Mode: 0o750},
		{Path: "owned", UID: 10001, GID: 10002, Mode: 0o4751},
		{Path: "shadowed", UID: 10003, GID: 10004, Mode: 0o640},
		{Path: "link", UID: 10007, GID: 10008, Mode: 0o777},
		{Path: "root-owned", UID: 0, GID: 0, Mode: 0o644},
	}})
	if err := os.Symlink("owned", filepath.Join(lower, layerFSDirName, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	upper := t.TempDir()
	writeLayer(t, upper, map[string]string{"shadowed": "upper"}, nil)
	before := make(map[string][2]uint32, 3)
	for _, path := range []string{"owned", "shadowed", "root-owned"} {
		fi, err := os.Lstat(filepath.Join(lower, layerFSDirName, path))
		if err != nil {
			t.Fatal(err)
		}
		owner := fi.Sys().(*syscall.Stat_t)
		before[path] = [2]uint32{owner.Uid, owner.Gid}
	}

	fixups, err := resolveOwnerFixups([]string{lower, upper})
	if err != nil {
		t.Fatalf("resolveOwnerFixups: %v", err)
	}
	got := make(map[string]ownedPath, len(fixups))
	for _, f := range fixups {
		got[f.Path] = f
	}
	if len(got) != 2 || got["owned"].UID != 10001 || got["link"].UID != 10007 {
		t.Errorf("owner fixups = %+v, want only owned file and symlink", fixups)
	}
	if _, ok := got["."]; ok {
		t.Errorf("root owner should be applied through upper metadata, got fixup %+v", got["."])
	}
	if _, ok := got["root-owned"]; ok {
		t.Errorf("root-owned path should not be fixed up: %+v", got["root-owned"])
	}
	if _, ok := got["shadowed"]; ok {
		t.Errorf("shadowed lower owner should not be fixed up: %+v", got["shadowed"])
	}

	for _, path := range []string{"owned", "shadowed", "root-owned"} {
		fi, err := os.Lstat(filepath.Join(lower, layerFSDirName, path))
		if err != nil {
			t.Fatal(err)
		}
		owner := fi.Sys().(*syscall.Stat_t)
		if owner.Uid != before[path][0] || owner.Gid != before[path][1] {
			t.Errorf("shared lower %q owner changed from %d:%d to %d:%d", path, before[path][0], before[path][1], owner.Uid, owner.Gid)
		}
	}
}

func TestResolveOwnerFixups_SymlinkAncestorHidesLowerPath(t *testing.T) {
	lower := t.TempDir()
	writeLayer(t, lower, map[string]string{
		"alias/file":     "hidden lower path",
		"elsewhere/file": "visible symlink target",
	}, &whiteoutSet{Owners: []ownedPath{{Path: "alias/file", UID: 10001, GID: 10002, Mode: 0o644}}})
	upper := t.TempDir()
	writeLayer(t, upper, nil, nil)
	if err := os.Symlink("elsewhere", filepath.Join(upper, layerFSDirName, "alias")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	fixups, err := resolveOwnerFixups([]string{lower, upper})
	if err != nil {
		t.Fatalf("resolveOwnerFixups: %v", err)
	}
	if len(fixups) != 0 {
		t.Errorf("fixups = %+v, want none because upper symlink hides alias/file", fixups)
	}
}

func TestImageRootMetadata_SelectsTopLayerAndDefaults(t *testing.T) {
	got, err := imageRootMetadata(nil)
	if err != nil {
		t.Fatalf("imageRootMetadata without layers: %v", err)
	}
	if got.Mode != 0o755 || got.UID != 0 || got.GID != 0 {
		t.Errorf("default root metadata = %+v, want 0755 root:root", got)
	}

	base, top := t.TempDir(), t.TempDir()
	writeLayer(t, base, nil, nil)
	writeLayer(t, top, nil, &whiteoutSet{Owners: []ownedPath{{Path: ".", UID: 10001, GID: 10002, Mode: 0o751}}})
	if err := os.Chmod(filepath.Join(base, layerFSDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(top, layerFSDirName), 0o751); err != nil {
		t.Fatal(err)
	}
	topInfo, err := os.Stat(filepath.Join(top, layerFSDirName))
	if err != nil {
		t.Fatal(err)
	}
	got, err = imageRootMetadata([]string{base, top})
	if err != nil {
		t.Fatalf("imageRootMetadata: %v", err)
	}
	if got.Mode.Perm() != 0o751 || got.UID != 10001 || got.GID != 10002 {
		t.Errorf("root metadata = %+v, want mode 0751 and top owner 10001:10002", got)
	}
	if owner := topInfo.Sys().(*syscall.Stat_t); owner.Uid != uint32(os.Getuid()) || owner.Gid != uint32(os.Getgid()) {
		t.Errorf("shared top layer root owner = %d:%d, want unchanged test owner %d:%d", owner.Uid, owner.Gid, os.Getuid(), os.Getgid())
	}
}

// A bundle without an overlay spec must be left untouched.
func TestSetupBundleRootfs_NoSpecIsNoop(t *testing.T) {
	bundle := t.TempDir()
	if err := SetupBundleRootfs(bundle); err != nil {
		t.Fatalf("SetupBundleRootfs: %v", err)
	}
	if entries, _ := os.ReadDir(bundle); len(entries) != 0 {
		t.Errorf("no-spec bundle was modified: %v", entries)
	}
}

// A zero-layer spec composes without any mount: empty rootfs plus ExtraDirs.
// Needs root for applying the default root:root metadata.
func TestSetupBundleRootfs_ZeroLayers(t *testing.T) {
	roottest.Require(t, "root:root chown for default rootfs metadata")
	bundle := t.TempDir()
	if err := WriteSpec(bundle, &OverlaySpec{Layers: nil, ExtraDirs: []string{"/run/ate"}}); err != nil {
		t.Fatalf("WriteSpec: %v", err)
	}
	if err := SetupBundleRootfs(bundle); err != nil {
		t.Fatalf("SetupBundleRootfs: %v", err)
	}
	fi, err := os.Stat(filepath.Join(bundle, "rootfs", "run", "ate"))
	if err != nil || !fi.IsDir() {
		t.Errorf("ExtraDir not created in rootfs: fi=%v err=%v", fi, err)
	}
	root, err := os.Stat(filepath.Join(bundle, "rootfs"))
	if err != nil {
		t.Fatal(err)
	}
	rootOwner := root.Sys().(*syscall.Stat_t)
	if root.Mode().Perm() != 0o755 || rootOwner.Uid != 0 || rootOwner.Gid != 0 {
		t.Errorf("empty rootfs metadata = %v %d:%d, want 0755 root:root", root.Mode().Perm(), rootOwner.Uid, rootOwner.Gid)
	}
	for _, d := range []string{"upper", "work"} {
		if fi, err := os.Stat(filepath.Join(bundle, d)); err != nil || !fi.IsDir() {
			t.Errorf("bundle dir %q missing: %v", d, err)
		}
	}
}

// Implicit-parent metadata repair through a real overlay: the base declares
// a 0700 dir, the top layer created it implicitly (0755 in its tree), and
// after compose the merged view must show 0700 — copied up into the
// bundle's upper, with the shared layer trees untouched. Needs root.
func TestSetupBundleRootfs_ImplicitDirMetadataRepair(t *testing.T) {
	roottest.Require(t, "mount/unmount")
	base := t.TempDir()
	writeLayer(t, base, map[string]string{"secret/keep.txt": "k"}, &whiteoutSet{Owners: []ownedPath{{Path: "secret", UID: 10011, GID: 10012, Mode: 0o700}}})
	if err := os.Chmod(filepath.Join(base, layerFSDirName, "secret"), 0o700); err != nil {
		t.Fatal(err)
	}
	top := t.TempDir()
	writeLayer(t, top, map[string]string{"secret/new.txt": "n"}, &whiteoutSet{ImplicitDirs: []string{"secret"}})

	bundle := t.TempDir()
	if err := WriteSpec(bundle, &OverlaySpec{Layers: []string{base, top}}); err != nil {
		t.Fatalf("WriteSpec: %v", err)
	}
	if err := SetupBundleRootfs(bundle); err != nil {
		t.Fatalf("SetupBundleRootfs: %v", err)
	}
	t.Cleanup(func() { _ = UnmountAllUnder(bundle) })

	fi, err := os.Lstat(filepath.Join(bundle, "rootfs", "secret"))
	if err != nil {
		t.Fatalf("stat merged dir: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("merged secret mode = %v, want 0700 from the declaring base layer", fi.Mode().Perm())
	}
	if owner := fi.Sys().(*syscall.Stat_t); owner.Uid != 10011 || owner.Gid != 10012 {
		t.Errorf("merged secret owner = %d:%d, want 10011:10012 from declaring base layer", owner.Uid, owner.Gid)
	}
	// The repair must land in the bundle upper, not the shared pool.
	if fi, err := os.Lstat(filepath.Join(top, layerFSDirName, "secret")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("shared top layer tree was modified: %v %v", fi, err)
	}
	if _, err := os.Lstat(filepath.Join(bundle, "upper", "secret")); err != nil {
		t.Errorf("repair did not copy up into the bundle upper: %v", err)
	}
}

// Full overlay mount and private-dir reset; needs mount and chown privileges.
func TestSetupBundleRootfs_MountAndUnmount(t *testing.T) {
	roottest.Require(t, "mount/unmount")
	layer := t.TempDir()
	writeLayer(t, layer, map[string]string{
		"from-layer.txt":       "hello",
		"owned-dir/nested.txt": "nested data",
	}, &whiteoutSet{Owners: []ownedPath{
		{Path: ".", UID: 10001, GID: 10002, Mode: 0o751},
		{Path: "from-layer.txt", UID: 10003, GID: 10004, Mode: 0o644},
		{Path: "owned-link", UID: 10005, GID: 10006, Mode: 0o777},
		{Path: "owned-dir", UID: 10007, GID: 10008, Mode: 0o700},
		{Path: "owned-dir/nested.txt", UID: 10009, GID: 10010, Mode: 0o600},
	}})
	if err := os.Symlink("from-layer.txt", filepath.Join(layer, layerFSDirName, "owned-link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	layerRoot := filepath.Join(layer, layerFSDirName)
	if err := os.Chmod(layerRoot, 0o751); err != nil {
		t.Fatal(err)
	}

	bundle := t.TempDir()
	if err := WriteSpec(bundle, &OverlaySpec{Layers: []string{layer}, ExtraDirs: []string{"/run/ate"}}); err != nil {
		t.Fatalf("WriteSpec: %v", err)
	}
	if err := SetupBundleRootfs(bundle); err != nil {
		t.Fatalf("SetupBundleRootfs: %v", err)
	}
	t.Cleanup(func() { _ = UnmountAllUnder(bundle) })

	if got, err := os.ReadFile(filepath.Join(bundle, "rootfs", "from-layer.txt")); err != nil || string(got) != "hello" {
		t.Errorf("layer content not visible through overlay: %q (%v)", got, err)
	}
	if fi, err := os.Stat(filepath.Join(bundle, "rootfs", "run", "ate")); err != nil || !fi.IsDir() {
		t.Errorf("ExtraDir missing in overlay: %v", err)
	}
	mergedRoot, err := os.Stat(filepath.Join(bundle, "rootfs"))
	if err != nil {
		t.Fatal(err)
	}
	mergedOwner := mergedRoot.Sys().(*syscall.Stat_t)
	if mergedRoot.Mode().Perm() != 0o751 || mergedOwner.Uid != 10001 || mergedOwner.Gid != 10002 {
		t.Errorf("merged root metadata = %v %d:%d, want 0751 10001:10002", mergedRoot.Mode().Perm(), mergedOwner.Uid, mergedOwner.Gid)
	}
	ownedFile, err := os.Lstat(filepath.Join(bundle, "rootfs", "from-layer.txt"))
	if err != nil {
		t.Fatal(err)
	}
	fileOwner := ownedFile.Sys().(*syscall.Stat_t)
	if fileOwner.Uid != 10003 || fileOwner.Gid != 10004 {
		t.Errorf("merged file owner = %d:%d, want 10003:10004", fileOwner.Uid, fileOwner.Gid)
	}
	if got, err := os.ReadFile(filepath.Join(bundle, "upper", "from-layer.txt")); err != nil || string(got) != "hello" {
		t.Errorf("owned file was not copied into bundle upper: %q (%v)", got, err)
	}
	link, err := os.Lstat(filepath.Join(bundle, "rootfs", "owned-link"))
	if err != nil {
		t.Fatal(err)
	}
	linkOwner := link.Sys().(*syscall.Stat_t)
	if linkOwner.Uid != 10005 || linkOwner.Gid != 10006 {
		t.Errorf("merged symlink owner = %d:%d, want 10005:10006", linkOwner.Uid, linkOwner.Gid)
	}
	ownedDir, err := os.Stat(filepath.Join(bundle, "rootfs", "owned-dir"))
	if err != nil {
		t.Fatal(err)
	}
	dirOwner := ownedDir.Sys().(*syscall.Stat_t)
	if ownedDir.Mode().Perm() != 0o700 || dirOwner.Uid != 10007 || dirOwner.Gid != 10008 {
		t.Errorf("merged owned dir = %v %d:%d, want 0700 10007:10008", ownedDir.Mode().Perm(), dirOwner.Uid, dirOwner.Gid)
	}
	layerFile, err := os.Lstat(filepath.Join(layer, layerFSDirName, "from-layer.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if owner := layerFile.Sys().(*syscall.Stat_t); owner.Uid != 0 || owner.Gid != 0 {
		t.Errorf("shared layer file was chowned: %d:%d", owner.Uid, owner.Gid)
	}
	// A write through the mount lands in the bundle's upper, not the layer.
	if err := os.WriteFile(filepath.Join(bundle, "rootfs", "written.txt"), []byte("w"), 0o644); err != nil {
		t.Fatalf("write through overlay: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bundle, "upper", "written.txt")); err != nil {
		t.Errorf("write did not land in upper: %v", err)
	}
	if _, err := os.Stat(filepath.Join(layer, layerFSDirName, "written.txt")); err == nil {
		t.Errorf("write leaked into the shared layer")
	}

	if err := UnmountAllUnder(bundle); err != nil {
		t.Fatalf("UnmountAllUnder: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bundle, "rootfs", "from-layer.txt")); err == nil {
		t.Errorf("rootfs still shows layer content after unmount")
	}
	for _, name := range []string{"rootfs", "upper", "work"} {
		fi, err := os.Stat(filepath.Join(bundle, name))
		if err != nil {
			t.Fatal(err)
		}
		owner := fi.Sys().(*syscall.Stat_t)
		if fi.Mode().Perm() != 0o700 || owner.Uid != 0 || owner.Gid != 0 {
			t.Errorf("%s metadata after unmount = %v %d:%d, want 0700 root:root", name, fi.Mode().Perm(), owner.Uid, owner.Gid)
		}
	}
	for _, name := range []string{"from-layer.txt", "owned-link", "owned-dir", "owned-dir/nested.txt"} {
		fi, err := os.Lstat(filepath.Join(bundle, "upper", name))
		if err != nil {
			t.Fatalf("upper copy-up %q missing after unmount: %v", name, err)
		}
		owner := fi.Sys().(*syscall.Stat_t)
		if owner.Uid != 0 || owner.Gid != 0 {
			t.Errorf("upper copy-up %q owner after unmount = %d:%d, want 0:0", name, owner.Uid, owner.Gid)
		}
		if fi.IsDir() && fi.Mode().Perm() != 0o700 {
			t.Errorf("upper dir %q mode after unmount = %v, want 0700", name, fi.Mode().Perm())
		}
	}
}

// Regression test for the mount(2) single-page option-string cap: a lowerdir
// chain whose joined paths exceed one page (~34 digest-derived layers) used
// to fail with a bare EINVAL. The fsconfig lowerdir+ path has no aggregate
// limit. Needs CAP_SYS_ADMIN.
func TestSetupBundleRootfs_ManyLayers(t *testing.T) {
	roottest.Require(t, "mount/unmount")
	// Digest-length dir names so each path matches production length (~114
	// bytes); 64 of them comfortably exceed the page that motivated this.
	pool := filepath.Join(t.TempDir(), "sha256")
	const n = 64
	layers := make([]string, n)
	joined := 0
	for i := range layers {
		layers[i] = filepath.Join(pool, fmt.Sprintf("%064d", i))
		writeLayer(t, layers[i], map[string]string{fmt.Sprintf("from-layer-%02d.txt", i): "x"}, nil)
		joined += len(layers[i]) + len("/fs") + 1
	}
	if pageSize := os.Getpagesize(); joined <= pageSize {
		t.Fatalf("test layers join to %d bytes, not exceeding the %d-byte page this test guards against", joined, pageSize)
	}

	bundle := t.TempDir()
	if err := WriteSpec(bundle, &OverlaySpec{Layers: layers}); err != nil {
		t.Fatalf("WriteSpec: %v", err)
	}
	if err := SetupBundleRootfs(bundle); err != nil {
		t.Fatalf("SetupBundleRootfs with %d layers: %v", n, err)
	}
	t.Cleanup(func() { _ = UnmountAllUnder(bundle) })

	// Bottom-most and top-most layers are both visible in the merged view.
	for _, i := range []int{0, n - 1} {
		p := filepath.Join(bundle, "rootfs", fmt.Sprintf("from-layer-%02d.txt", i))
		if _, err := os.Stat(p); err != nil {
			t.Errorf("layer %d content missing from merged rootfs: %v", i, err)
		}
	}

	if err := UnmountAllUnder(bundle); err != nil {
		t.Fatalf("UnmountAllUnder: %v", err)
	}
}

// Image volumes reach identical content through both arms: one layer binds,
// several overlay.
func TestSetupBundleRootfs_ImageVolumes(t *testing.T) {
	roottest.Require(t, "mount/unmount")

	for _, tc := range []struct {
		name   string
		layers int
	}{
		{"one layer binds", 1},
		{"three layers overlay", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var layers []string
			for i := range tc.layers {
				dir := t.TempDir()
				writeLayer(t, dir, map[string]string{
					fmt.Sprintf("layer%d.txt", i): "content",
					"shadowed.txt":                fmt.Sprintf("from-layer-%d", i),
				}, nil)
				layers = append(layers, dir)
			}

			bundle := t.TempDir()
			if err := WriteSpec(bundle, &OverlaySpec{
				Layers:       []string{layers[0]},
				ImageVolumes: []ImageVolumeOverlay{{Name: "agent", Layers: layers}},
			}); err != nil {
				t.Fatalf("WriteSpec: %v", err)
			}
			if err := SetupBundleRootfs(bundle); err != nil {
				t.Fatalf("SetupBundleRootfs: %v", err)
			}
			t.Cleanup(func() { _ = UnmountAllUnder(bundle) })

			mnt := filepath.Join(bundle, "volumes", "agent")
			for i := range tc.layers {
				if _, err := os.Stat(filepath.Join(mnt, fmt.Sprintf("layer%d.txt", i))); err != nil {
					t.Errorf("layer %d not visible in the volume: %v", i, err)
				}
			}
			// Later layers win, same as the rootfs overlay.
			want := fmt.Sprintf("from-layer-%d", tc.layers-1)
			if got, err := os.ReadFile(filepath.Join(mnt, "shadowed.txt")); err != nil || string(got) != want {
				t.Errorf("shadowed.txt = %q (%v), want %q", got, err, want)
			}
			// No upper on either arm, so there is nowhere for a write to go.
			if err := os.WriteFile(filepath.Join(mnt, "nope.txt"), []byte("x"), 0o644); err == nil {
				t.Error("write succeeded through a read-only image volume")
			} else if !errors.Is(err, unix.EROFS) {
				t.Errorf("write failed with %v, want EROFS", err)
			}
			// The shared pool must never see the attempt.
			if _, err := os.Stat(filepath.Join(layers[tc.layers-1], layerFSDirName, "nope.txt")); err == nil {
				t.Error("write leaked into the shared layer pool")
			}

			if err := UnmountAllUnder(bundle); err != nil {
				t.Fatalf("UnmountAllUnder: %v", err)
			}
			if _, err := os.Stat(filepath.Join(mnt, "layer0.txt")); err == nil {
				t.Error("volume still shows content after unmount")
			}
		})
	}
}
