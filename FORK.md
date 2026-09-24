# oldsj/substrate

A fork of [Agent Substrate](https://github.com/agent-substrate/substrate).

## Branches

- `main` mirrors upstream `main`.
- `patched` remains unchanged at `ce265c1dbd3775faf10c95f71f2c16ff3d47c332`, based on
  `cdac9baef81dd319b46086d695266e6161e9e592` plus its seven fork commits.
- `patched-next` is based on upstream `main` at
  `14c0c136bc3fda4d8e67de3851c087a28a2e754b` plus the patches below, one commit
  each. It is a local rebase candidate; consumers pin an exact commit after
  validation.
- `upstream/<topic>` holds one patch rebased onto upstream `main`, written as
  an upstream contribution. Each is staged as a pull request against this
  fork's `main`; none has been sent upstream.

## Patches on `patched-next`

| Patch | Staged as |
|---|---|
| `hack/create-kind-cluster.sh`: opt-in `DISABLE_DEFAULT_CNI`, `KIND_NODE_IMAGE`, `KIND_CONFIG_ONLY` | Not staged |
| atelet: run actor containers as the image's `USER` in its `WORKDIR` | `upstream/image-user-workdir` |
| atelet/ateom: preserve image root metadata and non-root layer ownership (regular-file ownership fixups copy file data into each bundle's upper) | Not staged |
| atelet/ateom: assign fresh durable volumes to the first rw non-root image user and preserve restored owners | Not staged |

## Updating

Moving a patched branch to a newer upstream commit means rebasing it, dropping
any patch upstream has since merged, and running the affected tests. Consumers
then move their pin.

## Actor capabilities

Actor containers run as the image's `USER`, and a template's
`securityContext.capabilities` apply to that user. Don't add `SETUID` or
`SETGID` to let a non-root image drop privileges at startup: the workload
would keep them.
