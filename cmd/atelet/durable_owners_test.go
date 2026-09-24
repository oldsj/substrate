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
	"reflect"
	"testing"

	"github.com/agent-substrate/substrate/internal/imagecache"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
)

func TestSelectDurableDirOwners(t *testing.T) {
	durable := func(name string) *ateletpb.Volume {
		return &ateletpb.Volume{Name: name, Source: &ateletpb.Volume_DurableDir{DurableDir: &ateletpb.DurableDirVolume{}}}
	}
	containers := []*ateletpb.Container{
		{Name: "root-first", VolumeMounts: []*ateletpb.VolumeMount{{Name: "data"}}},
		{Name: "first-user", VolumeMounts: []*ateletpb.VolumeMount{{Name: "other"}, {Name: "data"}, {Name: "data"}}},
		{Name: "second-user", VolumeMounts: []*ateletpb.VolumeMount{{Name: "cache"}, {Name: "data"}}},
	}
	users := map[string]processUser{
		"root-first":  {},
		"first-user":  {UID: 10001, GID: 10002},
		"second-user": {UID: 20001, GID: 20002},
	}

	got := selectDurableDirOwners(
		[]*ateletpb.Volume{durable("data"), durable("cache"), {Name: "other", Source: &ateletpb.Volume_Image{Image: &ateletpb.ImageVolumeSource{}}}},
		containers,
		users,
	)
	want := map[string][]imagecache.DurableDirOwner{
		"first-user":  {{Name: "data", UID: 10001, GID: 10002}},
		"second-user": {{Name: "cache", UID: 20001, GID: 20002}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("selectDurableDirOwners() = %#v, want %#v", got, want)
	}
}
