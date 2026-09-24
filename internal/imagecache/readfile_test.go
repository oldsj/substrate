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
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// testLayer describes one unpacked layer: files under fs/ and the whiteout
// state recorded at unpack time.
type testLayer struct {
	files     map[string]string
	symlinks  map[string]string
	whiteouts []string
	opaques   []string
}

func makeTestImage(t *testing.T, layers ...testLayer) *Image {
	t.Helper()
	img := &Image{}
	for _, l := range layers {
		dir := filepath.Join(t.TempDir(), "layer")
		fsDir := filepath.Join(dir, layerFSDirName)
		if err := os.MkdirAll(fsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range l.files {
			p := filepath.Join(fsDir, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for name, target := range l.symlinks {
			p := filepath.Join(fsDir, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
		}
		if len(l.whiteouts) > 0 || len(l.opaques) > 0 {
			b, err := json.Marshal(whiteoutSet{Version: 1, Whiteouts: l.whiteouts, Opaques: l.opaques})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, layerWhiteoutsFileName), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		img.LayerDirs = append(img.LayerDirs, dir)
	}
	return img
}

func TestImageReadFile(t *testing.T) {
	tests := []struct {
		name    string
		layers  []testLayer
		path    string
		want    string
		wantErr error
	}{{
		name:   "found in the only layer",
		layers: []testLayer{{files: map[string]string{"etc/passwd": "base"}}},
		path:   "/etc/passwd",
		want:   "base",
	}, {
		name: "top-most layer wins",
		layers: []testLayer{
			{files: map[string]string{"etc/passwd": "base"}},
			{files: map[string]string{"etc/passwd": "top"}},
		},
		path: "/etc/passwd",
		want: "top",
	}, {
		name: "falls through layers that lack the file",
		layers: []testLayer{
			{files: map[string]string{"etc/passwd": "base"}},
			{files: map[string]string{"usr/bin/tool": "x"}},
		},
		path: "/etc/passwd",
		want: "base",
	}, {
		name: "whiteout hides lower layers",
		layers: []testLayer{
			{files: map[string]string{"etc/passwd": "base"}},
			{whiteouts: []string{"etc/passwd"}},
		},
		path:    "/etc/passwd",
		wantErr: fs.ErrNotExist,
	}, {
		name: "whiteout of a parent directory hides lower layers",
		layers: []testLayer{
			{files: map[string]string{"etc/passwd": "base"}},
			{whiteouts: []string{"etc"}},
		},
		path:    "/etc/passwd",
		wantErr: fs.ErrNotExist,
	}, {
		name: "opaque parent directory hides lower layers",
		layers: []testLayer{
			{files: map[string]string{"etc/passwd": "base"}},
			{files: map[string]string{"etc/hostname": "h"}, opaques: []string{"etc"}},
		},
		path:    "/etc/passwd",
		wantErr: fs.ErrNotExist,
	}, {
		name: "a file re-added above a whiteout is visible",
		layers: []testLayer{
			{files: map[string]string{"etc/passwd": "base"}},
			{whiteouts: []string{"etc/passwd"}},
			{files: map[string]string{"etc/passwd": "readded"}},
		},
		path: "/etc/passwd",
		want: "readded",
	}, {
		name: "a file where a parent directory would be hides lower layers",
		layers: []testLayer{
			{files: map[string]string{"etc/passwd": "base"}},
			{files: map[string]string{"etc": "not a directory"}},
		},
		path:    "/etc/passwd",
		wantErr: fs.ErrNotExist,
	}, {
		name:    "missing everywhere",
		layers:  []testLayer{{files: map[string]string{"etc/hostname": "h"}}},
		path:    "/etc/passwd",
		wantErr: fs.ErrNotExist,
	}, {
		name:   "symlink within the layer is followed",
		layers: []testLayer{{files: map[string]string{"usr/lib/passwd": "linked"}, symlinks: map[string]string{"etc/passwd": "../usr/lib/passwd"}}},
		path:   "/etc/passwd",
		want:   "linked",
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			img := makeTestImage(t, tc.layers...)
			got, err := img.ReadFile(tc.path)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ReadFile(%q) = %q, %v; want error %v", tc.path, got, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadFile(%q) error: %v", tc.path, err)
			}
			if string(got) != tc.want {
				t.Errorf("ReadFile(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// A symlink cannot make ReadFile read outside the layer's tree.
func TestImageReadFile_SymlinkCannotEscapeLayer(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("host file"), 0o644); err != nil {
		t.Fatal(err)
	}
	img := makeTestImage(t, testLayer{symlinks: map[string]string{"etc/passwd": outside}})
	got, err := img.ReadFile("/etc/passwd")
	if err == nil {
		t.Fatalf("ReadFile followed an escaping symlink and returned %q", got)
	}
}

func TestImageReadFile_RejectsNonRegularAndOversized(t *testing.T) {
	img := makeTestImage(t, testLayer{files: map[string]string{"etc/passwd/child": "x"}})
	if _, err := img.ReadFile("/etc/passwd"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile on a directory = %v, want a non-ErrNotExist error", err)
	}

	big := make([]byte, maxImageFileSize+1)
	img = makeTestImage(t, testLayer{files: map[string]string{"etc/passwd": string(big)}})
	if _, err := img.ReadFile("/etc/passwd"); err == nil {
		t.Error("ReadFile on an oversized file succeeded, want error")
	}
}

func TestImageReadFile_InvalidPath(t *testing.T) {
	img := makeTestImage(t, testLayer{})
	for _, p := range []string{"", "/", "../etc/passwd"} {
		if _, err := img.ReadFile(p); err == nil {
			t.Errorf("ReadFile(%q) succeeded, want error", p)
		}
	}
}
