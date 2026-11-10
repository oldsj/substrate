# oldsj/substrate

A fork of [Agent Substrate](https://github.com/agent-substrate/substrate).

## Branches

- `main` mirrors upstream `main`.
- `patched` is upstream `main` plus the patches below. Updates merge upstream
  `main` into it, so the branch only moves forward.
- `upstream/<topic>` holds one patch rebased onto upstream `main`, written as
  an upstream contribution. None has been sent upstream.

## Patches on `patched`

| Patch | Staged as |
|---|---|
| `hack/create-kind-cluster.sh`: opt-in `DISABLE_DEFAULT_CNI`, `KIND_NODE_IMAGE`, `KIND_CONFIG_ONLY` | Not staged |

## Dropped patches

Upstream v1.0.0 covers these, so the fork no longer carries them.

| Patch | Upstream |
|---|---|
| atelet: run actor containers as the image's `USER` in its `WORKDIR` | agent-substrate/substrate#2392 |
| atelet/ateom: preserve image root metadata and non-root layer ownership | agent-substrate/substrate#2392 |
| atelet/ateom: assign fresh durable volumes to the first non-root image user | Not ported. Upstream creates a `durableDir` `0777` and root-owned (agent-substrate/substrate#3457), so any user can write it but none owns it. |

## Updating

Merge upstream `main` into a branch off `patched`, drop any patch upstream has
since merged, and run the affected tests. Consumers then move their pin.
