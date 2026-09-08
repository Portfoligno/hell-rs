# Pinned runtime manifests

These are the unchanged `runtime-manifest.json` members from the MemCordon
`0.5.2-rc.23` release archives pinned by `ci/memcordon-runtime-v1.toml`.
Both downloaded archive byte lengths and SHA256 digests were verified against
that lock before extracting the fixtures.

| Fixture | Archive SHA256 |
| --- | --- |
| `runtime-manifest-linux.json` | `839c4918eef67be4e6a773e7f0840d0665480a4c0d874c72432a208315db479d` |
| `runtime-manifest-windows.json` | `90047dd584bcec2206314aeccf6555d51c4c123f7769a89a29489b0e06316278` |

The producer records component identities, roles, paths, sizes, modes, digests,
and sealed protocol authority. The containing archive digest is independently
pinned; it is not a field in its embedded runtime manifest.
