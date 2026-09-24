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
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/roottest"
)

func TestApplyInitialDurableDirOwners(t *testing.T) {
	roottest.Require(t, "changing a durable volume directory owner requires CAP_CHOWN")

	tests := []struct {
		name     string
		uid      uint32
		gid      uint32
		populate bool
		wantUID  uint32
		wantGID  uint32
	}{
		{name: "fresh empty directory gets image owner", uid: 10001, gid: 10002, wantUID: 10001, wantGID: 10002},
		{name: "non-empty directory is preserved", uid: 10001, gid: 10002, populate: true},
		{name: "root image keeps root owner"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			oldActorsDir := ateompath.ActorsDir
			ateompath.ActorsDir = t.TempDir()
			t.Cleanup(func() { ateompath.ActorsDir = oldActorsDir })

			const actorUID = "actor"
			const containerName = "app"
			volumePath := ateompath.DurableDirVolumeMountPoint(actorUID, "data")
			bundlePath := ateompath.OCIBundlePath(actorUID, containerName)
			if err := os.MkdirAll(volumePath, 0o700); err != nil {
				t.Fatalf("creating volume directory: %v", err)
			}
			if err := os.MkdirAll(bundlePath, 0o700); err != nil {
				t.Fatalf("creating bundle directory: %v", err)
			}
			if tc.populate {
				if err := os.WriteFile(filepath.Join(volumePath, "existing"), []byte("keep"), 0o600); err != nil {
					t.Fatalf("creating existing content: %v", err)
				}
			}
			if err := WriteSpec(bundlePath, &OverlaySpec{
				DurableDirOwners: []DurableDirOwner{{Name: "data", UID: tc.uid, GID: tc.gid}},
			}); err != nil {
				t.Fatalf("writing overlay spec: %v", err)
			}

			if err := ApplyInitialDurableDirOwners(actorUID, []string{containerName}); err != nil {
				t.Fatalf("ApplyInitialDurableDirOwners: %v", err)
			}

			info, err := os.Stat(volumePath)
			if err != nil {
				t.Fatalf("stating volume directory: %v", err)
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				t.Fatal("volume directory has no syscall.Stat_t")
			}
			if stat.Uid != tc.wantUID || stat.Gid != tc.wantGID {
				t.Errorf("volume owner = %d:%d, want %d:%d", stat.Uid, stat.Gid, tc.wantUID, tc.wantGID)
			}
			if tc.populate {
				if got, err := os.ReadFile(filepath.Join(volumePath, "existing")); err != nil || string(got) != "keep" {
					t.Errorf("existing content = %q, %v; want keep", got, err)
				}
			}
		})
	}
}
