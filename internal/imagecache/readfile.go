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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// maxImageFileSize bounds ReadFile. It exists for small config files such as
// /etc/passwd, not for arbitrary image content.
const maxImageFileSize = 1 << 20

// errHiddenInLayer reports that a layer's own entry hides the path in every
// lower layer: a finalized whiteout, or a non-directory where a parent
// directory would be.
var errHiddenInLayer = errors.New("hidden by layer")

// ReadFile returns the contents of the regular file name as the image's
// composed rootfs would show it, without mounting anything: the top-most
// layer that has the file wins, and a whiteout or opaque directory recorded
// at unpack time hides it in every lower layer. The error wraps
// fs.ErrNotExist when no layer provides the file.
//
// Reads are confined to each layer's tree, so a symlink cannot reach outside
// it; a symlink whose target lives in another layer is not resolved.
func (img *Image) ReadFile(name string) ([]byte, error) {
	rel, skip, err := validateTarName(name)
	if err != nil {
		return nil, fmt.Errorf("invalid image path %q: %w", name, err)
	}
	if skip {
		return nil, fmt.Errorf("invalid image path %q", name)
	}

	for i := len(img.LayerDirs) - 1; i >= 0; i-- {
		layerDir := img.LayerDirs[i]
		b, err := readLayerFile(layerDir, rel)
		if err == nil {
			return b, nil
		}
		if errors.Is(err, errHiddenInLayer) {
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		hidden, err := layerHides(layerDir, rel)
		if err != nil {
			return nil, err
		}
		if hidden {
			break
		}
	}
	return nil, fmt.Errorf("%q in image %s: %w", name, img.Digest, fs.ErrNotExist)
}

// readLayerFile reads rel from one layer's fs/ tree. A path the layer does
// not have reports fs.ErrNotExist; one the layer hides reports
// errHiddenInLayer.
func readLayerFile(layerDir, rel string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Join(layerDir, layerFSDirName))
	if err != nil {
		return nil, fmt.Errorf("while opening layer fs in %q: %w", layerDir, err)
	}
	defer root.Close()

	// Stat before opening: opening a whiteout device or a FIFO would fail or
	// block.
	fi, err := root.Stat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fs.ErrNotExist
	} else if errors.Is(err, syscall.ENOTDIR) {
		return nil, errHiddenInLayer
	} else if err != nil {
		return nil, fmt.Errorf("while statting %q in layer %q: %w", rel, layerDir, err)
	}
	if fi.Mode()&fs.ModeCharDevice != 0 {
		return nil, errHiddenInLayer
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%q in layer %q is not a regular file", rel, layerDir)
	}

	f, err := root.Open(rel)
	if err != nil {
		return nil, fmt.Errorf("while opening %q in layer %q: %w", rel, layerDir, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxImageFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("while reading %q in layer %q: %w", rel, layerDir, err)
	}
	if len(b) > maxImageFileSize {
		return nil, fmt.Errorf("%q in layer %q is larger than %d bytes", rel, layerDir, maxImageFileSize)
	}
	return b, nil
}

// layerHides reports whether layerDir's whiteouts or opaque directories hide
// rel in the layers below it.
func layerHides(layerDir, rel string) (bool, error) {
	wh, err := readWhiteouts(layerDir)
	if err != nil {
		return false, err
	}
	for _, w := range wh.Whiteouts {
		if rel == w || strings.HasPrefix(rel, w+"/") {
			return true, nil
		}
	}
	for _, o := range wh.Opaques {
		if strings.HasPrefix(rel, o+"/") {
			return true, nil
		}
	}
	return false, nil
}
