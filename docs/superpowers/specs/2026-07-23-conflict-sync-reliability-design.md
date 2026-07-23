# Conflict Sync Reliability Design

## Objective

Make encrypted item-conflict handling demonstrably reliable across two authorized devices. An offline edit must remain a ciphertext-only candidate until an authorized writer explicitly keeps the remote version, promotes the local candidate, or submits a manual client-side merge.

## Scope

This work hardens the existing conflict feature. It does not introduce automatic merge, last-write-wins, distributed rate limiting, new plaintext server processing, or a public metrics endpoint.

## Design

The server remains the authority for item revisions and conflict state. A stale update or delete creates an `open` candidate in `item_conflicts`, with only revision metadata, actor ID, candidate kind, and an optional encrypted envelope. While any candidate is open for an item, regular mutations are rejected; subsequent stale writes remain preserved as candidates.

Resolution is atomic per item. `remote` closes all open candidates without promoting an envelope; `local` promotes the selected update candidate or confirms its delete; `merge` accepts only a fresh ciphertext envelope produced after local decryption. A resolution advances the vault revision even when remote is kept, so every device's normal sync-status check observes the change and atomically removes stale cached conflicts.

The CLI remains the only plaintext-processing component. `conflict list` uses the local encrypted cache and exposes IDs/metadata only. `conflict show` unlocks locally and decrypts remote plus candidate versions. `conflict resolve` obtains the latest cached revision, applies the selected decision or field-level manual merge locally, then sends the ciphertext envelope and revision precondition.

## Verification

Add server integration coverage for writer/viewer authorization, stale update/delete `409` responses, conflict sync, and each resolution outcome. Add a two-device end-to-end scenario: A and B edit offline from the same revision; A syncs; B syncs and retains its candidate; an authorized writer resolves; both caches converge after ordinary sync. Add CLI tests for parser, list redaction, show decryption, local/remote resolution, manual merge construction, and cache cleanup. Tests must assert that API bodies, cache rows, audit metadata, and logs do not contain the item plaintext.

## Acceptance Criteria

- Multiple offline candidates survive until one resolution closes the item set.
- Readers can list/show synchronized conflicts but cannot resolve them.
- Writers can resolve only with the current revision precondition.
- A remote-only resolution is visible through normal sync without a force-full operation.
- No endpoint, audit record, cache schema, or log stores plaintext item data.
