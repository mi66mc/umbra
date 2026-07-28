# Encrypted Local Cache Design

## Objective

Protect the entire persistent CLI cache, including operational metadata, with authenticated encryption while preserving Umbra's zero-knowledge server boundary.

## Decision

The SQLite working database lives only in process memory. On every successful cache mutation the client serializes that database in memory, encrypts the complete byte stream with the existing XChaCha20-Poly1305 envelope implementation, binds it to the profile and format version with AAD, and atomically replaces `cache.enc`. A random 32-byte cache key is held only in the OS keychain under a distinct versioned account name. The encrypted file is a versioned JSON envelope and contains no clear SQLite header, rows, keys, or fixtures.

This avoids a new SQLCipher native dependency and key-handling path. It keeps SQLite's query model while preventing plaintext database, journal, WAL, or temporary snapshot files from being written to disk.

## Failure and recovery behavior

- Missing encrypted cache creates an empty in-memory schema; a key is created only with the first successful snapshot.
- Missing key, invalid envelope, wrong AAD, unsupported version, or tampered ciphertext fails closed. The artifact is retained and no empty cache replaces it.
- Snapshot writes use a same-directory randomized temporary file and atomic promotion, so a failed write preserves the previous valid snapshot.
- A legacy `cache.db` is detected before opening and left untouched. The client refuses it rather than deleting or rewriting it automatically. Operators back it up offline, remove it intentionally, then sync again.
- `cache clear` removes the encrypted snapshot and matching keyring key. `lock` continues to clear transient unlock state only.

## Boundary and limits

The server receives exactly the existing ciphertext envelopes and metadata; cache keys, SQLite bytes, decrypted content and plaintext never cross the network. This protects a stolen cache file and metadata, not a running compromised user session, OS-keychain compromise, process memory while the CLI runs, or old filesystem backups of a legacy cache.

## Verification

Tests use an injected memory key store and temporary directories to prove normal reopen/offline reads, legacy refusal, absent/wrong key refusal, ciphertext tamper detection, failed promotion preservation, cleanup, and absence of plaintext/key fixtures from encrypted artifacts. Existing cache behavior tests continue to use explicit in-memory storage.

