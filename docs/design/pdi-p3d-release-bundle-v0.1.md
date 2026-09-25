# P3D Release-Input Bundle V0.1

Status: MU13-P3D Gate B implementation candidate. The CI artifact is
`QUALIFICATION_ONLY`; it is not a production OS/runtime authority and cannot
install, promote, or activate a release.

## Authority chain

The builder requires an exact clean 40-character candidate SHA. Git commands
use `/usr/bin/git`, a private `HOME`, `GIT_OPTIONAL_LOCKS=0`, no system/global
Git configuration, and never use a PR merge ref as the candidate. It creates a
self-contained Git bundle and proves it in an empty repository. Wheel and sdist
artifacts are built from `git archive` bytes for that candidate. The wheel is
then installed without dependencies into a fresh builder environment; the
bundle assembly implementation executed after that point is the implementation
inside the candidate wheel. Its artifact identity is the candidate wheel hash.

The OS runtime contract is an explicit `OSRuntimeManifestV1` input. CI uses
`.github/p3d/qualification-os-runtime.json`, which is deliberately not a
production target manifest. Production input authority must be separately
reviewed in a later gate.

Runtime dependencies are resolved as binary wheels only for the explicit
Python/ABI/platform target. The resulting `WheelhouseManifestV1` is computed
from wheel metadata and bytes. `requirements/runtime.lock` is derived from that
inventory and contains one exact version and SHA-256 per wheel. Verification
installs into a fresh venv with `--no-index`, `--find-links`, and
`--require-hashes`, then runs `pip check` and imports `pdi`, `psycopg`, and
`sqlalchemy`.

## Fixed archive layout

```text
manifests/files.json
manifests/os-runtime.json
manifests/release-input.json
manifests/wheelhouse.json
provenance/provenance.json
source/pdi.git.bundle
dist/pdi-<version>.tar.gz
wheelhouse/*.whl
requirements/runtime.lock
systemd/pdi-scoped-pipeline@.service
systemd/<six canonical enrichment timers>
```

`files.json` covers every payload file but excludes the five authority files
that would otherwise create a hash cycle. The outer verifier requires the
archive member set to equal the payload manifest plus those five files.

The uncompressed tar is canonical: sorted regular files only, mode 0644,
uid/gid 0, empty owner/group names, and mtime 0. Verification rejects absolute
or parent paths, duplicates, links, devices, FIFOs, unexpected members, and
metadata drift before copying any member. The PAX format is used solely so
standard wheel filenames longer than 100 UTF-8 bytes remain unchanged; for
such a member the verifier permits exactly one `path` header equal to the
validated member name, and rejects all other extended metadata. It never calls
`extractall()`.

The systemd set is exactly one generic service and six enrichment timers. Its
fingerprint covers exact source path, future canonical target path, content
hash, and expected mode. Dynamic protected profiles are Gate C inputs and are
not part of this static set.

## Provenance and attestation

`P3DReleaseBundleProvenanceV1` binds repository, candidate, workflow path and
workflow source SHA, run/attempt, fixed artifact identity, builder identity,
Git bundle, wheel, sdist, wheelhouse, OS manifest, systemd set, runtime lock,
and file manifest. `ReleaseInputBundleManifestV1` binds its canonical hash.

CI checks out `github.event.pull_request.head.sha`, validates exact HEAD and a
clean tree, builds the bundle, verifies it offline from archive bytes, and uses
the GitHub-owned `actions/attest-build-provenance` action pinned to a reviewed
full commit SHA. An independent step runs `gh attestation verify` against the
repository before rerunning the bundle verifier and offline install proof.

The bundle can vary between CI runs because run identity is provenance input.
Within one input set, canonical JSON, runtime lock, wheel inventory, OS
fingerprint, systemd fingerprint, member ordering, and archive metadata are
deterministic. Distribution builders may embed legitimate build metadata, so
wheel/sdist authority is their exact digest plus trusted provenance rather than
an unsupported claim of cross-run reproducibility.

## Security boundary

The code writes only caller-selected build/output or disposable temporary
directories. It has no sudo, apt, systemctl, `/opt`, `/etc`, `/var/lib`,
production database, provider, promotion, activation, or rehearsal capability.
The GitHub secret scanner covers repository history; canonical contract schemas
reject secret-shaped fields. A Git bundle necessarily contains the reviewed
source history and is therefore not inspected with naive marker matching that
would confuse safe configuration names with secret values.
