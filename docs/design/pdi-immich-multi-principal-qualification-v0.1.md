# Immich multi-Principal qualification v0.1

MU10 qualifies the DB-per-Principal architecture against an isolated Immich
v3.1 server. It does not promote the scoped runtime or alter production.

## Account and credential boundary

An Immich User UUID is the Provider Account's native identity. An API key is a
rotatable Credential. For scoped composition, `ImmichAdapter` and
`ImmichRepresentationAdapter` receive the expected User UUID and authenticate
`GET /api/users/me` before trusting the credential. A valid key owned by a
different user therefore fails before metadata discovery, Source/state writes,
or Resource Access. The legacy single-user composition may omit the expected
identity during transition and retains its existing server-health connection
check.

The disposable ordinary-user keys used these non-admin permissions:

- `user.read`
- `asset.read`
- `asset.view`
- `asset.download`
- `album.read`

Admin authentication was used only to provision the two disposable ordinary
users. User sessions performed synthetic uploads, metadata mutation, API-key
creation/revocation, and sharing. PDI ingestion and Resource Access used only
the ordinary users' API keys.

## Qualification topology and results

The real-provider test uses an isolated Docker network, private PostgreSQL and
Valkey instances, disposable media/database volumes, and a loopback-only Immich
endpoint. Two ordinary users each own a distinct JPEG and MP4. Two independently
provisioned Personal PDI databases contain their own Provider Instance,
Provider Account (including the remote User UUID), and Observation Scope.

The qualification proves:

- each API key discovers only its owner's private library;
- direct cross-account original access is denied;
- scoped full ingestion creates only non-NULL Scope provenance in the correct
  Personal database;
- a valid wrong-user key fails before scan or database mutation;
- thumbnail, preview, video, and byte-range video access use the exact Scope
  credential, and a valid wrong-user key is rejected during account proof;
- independent `metadata_updated_at_v1` state advances without cross-database
  mutation or legacy `provider_sync_state` writes;
- the five-minute overlap can replay without duplicate Source creation;
- authoritative deletion reconciliation in one Personal World leaves the other
  unchanged; and
- API-key rotation for the same remote User UUID preserves Account, Scope,
  Source, Asset, resource reference, and Scope-state identity, while another
  user's key is rejected as a rotation.

Immich shared-album access was proven through the recipient's ordinary user
credential. The current Adapter's owned-library metadata search did not include
that shared asset, so shared-content ingestion is explicitly
`NOT_SUPPORTED_BY_CURRENT_ADAPTER_SCOPE`; no Source was manufactured and scan
semantics were not broadened. Immich v3.1 exposed no safe reversible ordinary
user disable operation used by this Gate, so key revocation supplied the
reversible credential-invalid proof.

## Boundaries that remain

The Provider-specific identity probe is shared at the account-payload validation
layer while synchronous ingestion and asynchronous Resource Access retain their
appropriate HTTP clients. Raw API keys are not persisted in the Personal World,
logged, or embedded in exceptions. Endpoint location is not Provider Instance
identity.

Production Immich configuration, data, credentials, Sources, checkpoints,
pipelines, and Resource Access remain unchanged. Production account binding,
backfill/state copy, orchestration promotion, and real household onboarding
require later explicitly authorized Gates.
