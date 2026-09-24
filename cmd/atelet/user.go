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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// processUser is the numeric identity a container's process runs as.
type processUser struct {
	UID uint32
	GID uint32
}

// resolveProcessUser maps an image config's User onto numeric IDs the way
// containerd does. The forms are "", "user" and "user:group", where each
// part is a number or a name. Names are looked up in the image's /etc/passwd
// and /etc/group. A user given without a group takes its primary group from
// /etc/passwd, or 0 when the image has no entry for it. An empty User is
// root.
func resolveProcessUser(readFile func(string) ([]byte, error), user string) (processUser, error) {
	if user == "" {
		return processUser{}, nil
	}
	userPart, groupPart, hasGroup := strings.Cut(user, ":")
	if userPart == "" || (hasGroup && groupPart == "") {
		return processUser{}, fmt.Errorf("invalid image user %q", user)
	}

	var out processUser
	uid, uidIsNumeric := parseID(userPart)
	if uidIsNumeric && hasGroup {
		out.UID = uid
	} else {
		entries, err := readIDFile(readFile, "/etc/passwd", true)
		if err != nil {
			return processUser{}, err
		}
		entry, found := findEntry(entries, userPart, uidIsNumeric, uid)
		switch {
		case found:
			out.UID, out.GID = entry.id, entry.primaryGID
		case uidIsNumeric:
			out.UID = uid
		default:
			return processUser{}, fmt.Errorf("image user %q not found in /etc/passwd", userPart)
		}
	}
	if !hasGroup {
		return out, nil
	}

	gid, gidIsNumeric := parseID(groupPart)
	if gidIsNumeric {
		out.GID = gid
		return out, nil
	}
	entries, err := readIDFile(readFile, "/etc/group", false)
	if err != nil {
		return processUser{}, err
	}
	entry, found := findEntry(entries, groupPart, false, 0)
	if !found {
		return processUser{}, fmt.Errorf("image group %q not found in /etc/group", groupPart)
	}
	out.GID = entry.id
	return out, nil
}

// resolveWorkingDir returns the process cwd for an image config's
// WorkingDir: "/" when unset, otherwise the cleaned absolute path.
func resolveWorkingDir(workingDir string) (string, error) {
	if workingDir == "" {
		return "/", nil
	}
	if !path.IsAbs(workingDir) {
		return "", fmt.Errorf("image working directory %q is not absolute", workingDir)
	}
	return path.Clean(workingDir), nil
}

// idEntry is one line of /etc/passwd or /etc/group. primaryGID is only set
// for passwd entries.
type idEntry struct {
	name       string
	id         uint32
	primaryGID uint32
}

func parseID(s string) (uint32, bool) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// readIDFile parses an image's /etc/passwd (withPrimaryGID) or /etc/group. A
// missing file is an empty database; malformed lines are skipped, as libc
// does.
func readIDFile(readFile func(string) ([]byte, error), name string, withPrimaryGID bool) ([]idEntry, error) {
	b, err := readFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("while reading image %s: %w", name, err)
	}

	var entries []idEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 || fields[0] == "" {
			continue
		}
		id, ok := parseID(fields[2])
		if !ok {
			continue
		}
		e := idEntry{name: fields[0], id: id}
		if withPrimaryGID {
			if len(fields) < 4 {
				continue
			}
			if e.primaryGID, ok = parseID(fields[3]); !ok {
				continue
			}
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("while parsing image %s: %w", name, err)
	}
	return entries, nil
}

// findEntry returns the first entry matching by ID when byID is set,
// otherwise by name.
func findEntry(entries []idEntry, name string, byID bool, id uint32) (idEntry, bool) {
	for _, e := range entries {
		if (byID && e.id == id) || (!byID && e.name == name) {
			return e, true
		}
	}
	return idEntry{}, false
}
