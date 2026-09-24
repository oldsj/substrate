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
	"errors"
	"fmt"
	"io/fs"
	"testing"
)

const testPasswd = `root:x:0:0:root:/root:/bin/bash
# a comment
malformed-line
badid:x:notanumber:1::/:/bin/false
agent:x:10001:10002::/home/agent:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
`

const testGroup = `root:x:0:
agent:x:10002:
staff:x:50:agent
`

// fakeImageFiles serves files by absolute path; anything else does not exist.
func fakeImageFiles(files map[string]string) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		if s, ok := files[name]; ok {
			return []byte(s), nil
		}
		return nil, fmt.Errorf("%q: %w", name, fs.ErrNotExist)
	}
}

func TestResolveProcessUser(t *testing.T) {
	withDB := fakeImageFiles(map[string]string{"/etc/passwd": testPasswd, "/etc/group": testGroup})
	noDB := fakeImageFiles(nil)

	tests := []struct {
		name     string
		files    func(string) ([]byte, error)
		user     string
		want     processUser
		wantFail bool
	}{
		{name: "empty is root", files: withDB, user: "", want: processUser{}},
		{name: "numeric user takes its passwd primary group", files: withDB, user: "10001", want: processUser{UID: 10001, GID: 10002}},
		{name: "numeric user without a passwd entry gets group 0", files: withDB, user: "4242", want: processUser{UID: 4242}},
		{name: "numeric user with no passwd file", files: noDB, user: "10001", want: processUser{UID: 10001}},
		{name: "numeric user and group need no lookup", files: noDB, user: "10001:10001", want: processUser{UID: 10001, GID: 10001}},
		{name: "named user", files: withDB, user: "agent", want: processUser{UID: 10001, GID: 10002}},
		{name: "named user and group", files: withDB, user: "agent:staff", want: processUser{UID: 10001, GID: 50}},
		{name: "named user with numeric group", files: withDB, user: "agent:7", want: processUser{UID: 10001, GID: 7}},
		{name: "numeric user with named group", files: withDB, user: "10001:staff", want: processUser{UID: 10001, GID: 50}},
		{name: "unknown user name", files: withDB, user: "ghost", wantFail: true},
		{name: "unknown group name", files: withDB, user: "agent:ghosts", wantFail: true},
		{name: "named user with no passwd file", files: noDB, user: "agent", wantFail: true},
		{name: "malformed passwd line is skipped", files: withDB, user: "badid", wantFail: true},
		{name: "empty user part", files: withDB, user: ":0", wantFail: true},
		{name: "empty group part", files: withDB, user: "agent:", wantFail: true},
		{name: "uid out of range is treated as a name", files: withDB, user: "4294967296", wantFail: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveProcessUser(tc.files, tc.user)
			if tc.wantFail {
				if err == nil {
					t.Fatalf("resolveProcessUser(%q) = %+v, want error", tc.user, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveProcessUser(%q) error: %v", tc.user, err)
			}
			if got != tc.want {
				t.Errorf("resolveProcessUser(%q) = %+v, want %+v", tc.user, got, tc.want)
			}
		})
	}
}

// A read failure must propagate rather than being treated as a missing file.
func TestResolveProcessUser_ReadErrorPropagates(t *testing.T) {
	boom := errors.New("boom")
	_, err := resolveProcessUser(func(string) ([]byte, error) { return nil, boom }, "agent")
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want wrapped %v", err, boom)
	}
}

func TestResolveWorkingDir(t *testing.T) {
	tests := []struct {
		in       string
		want     string
		wantFail bool
	}{
		{in: "", want: "/"},
		{in: "/", want: "/"},
		{in: "/work/repo", want: "/work/repo"},
		{in: "/work//repo/../app/", want: "/work/app"},
		{in: "relative", wantFail: true},
	}
	for _, tc := range tests {
		got, err := resolveWorkingDir(tc.in)
		if tc.wantFail {
			if err == nil {
				t.Errorf("resolveWorkingDir(%q) error = nil, want error", tc.in)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("resolveWorkingDir(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}
