# Umbra Crypto Model

Umbra's cryptography is client-side. The server stores encrypted envelopes and policy metadata only.

## Initial Suite

```txt
KDF: Argon2id
Key separation: HKDF-SHA256
Encryption: XChaCha20-Poly1305
Recipient key agreement: X25519 ephemeral ECDH
Nonce: 24 random bytes
Envelope: JSON v1
```

The initial implementation uses:

```txt
argon2
chacha20poly1305
hkdf
sha2
x25519-dalek
rand_core
base64ct
zeroize
subtle
```

## Account KEK

The account key-encryption key is derived from:

```txt
master_password + user_secret_key + salt + Argon2id params
```

It opens the encrypted user private key. It should not directly encrypt every vault item.

## User Keypair

Each user has an asymmetric keypair:

```txt
public_key
private_key
```

The public key can be stored on the server and used by other authorized clients to wrap vault keys for the user. The private key is encrypted with `account_kek`.

Changing the user's password should only require re-encrypting the private key, not every vault key and item.

The MVP user keypair is an X25519 encryption keypair, not a signing keypair. Device signatures can be added later with a separate signature key.

## Vault Keys

Each vault has a random vault key:

```txt
vault_key = random 32 bytes
```

Items in that vault are encrypted with keys derived from the vault key. The vault key is wrapped for each authorized recipient.

Vault key wrapping uses:

```txt
ephemeral X25519 private key + recipient X25519 public key
  -> shared secret
  -> HKDF-SHA256 with wrapping AAD
  -> XChaCha20-Poly1305 key
```

## AAD

AAD means additional authenticated data.

It is not secret, but it is cryptographically protected from tampering. In Umbra, AAD binds ciphertext to its expected context. For an item, AAD should include:

```txt
app = "umbra"
purpose = "item"
schema = 1
vault_id
item_id
revision
kind
```

If an attacker copies ciphertext from one item, vault, kind, or revision into another context, decryption must fail.

The client should reconstruct expected AAD deterministically from trusted context and compare it to the envelope context. The envelope may include AAD for inspection, but decrypt must not blindly trust arbitrary AAD supplied by the server.

## Envelope V1

```json
{
  "version": 1,
  "suite": "UMBRA_XCHACHA20POLY1305_HKDFSHA256_V1",
  "nonce": "base64url...",
  "aad": {
    "app": "umbra",
    "purpose": "item",
    "schema": 1,
    "vault_id": "...",
    "item_id": "...",
    "revision": 1,
    "kind": "login"
  },
  "ciphertext": "base64url..."
}
```

## Wrapped Vault Key V1

```json
{
  "version": 1,
  "type": "vault_key_wrapping",
  "wrapping": {
    "method": "user_public_key",
    "recipient_public_key": "base64url...",
    "ephemeral_public_key": "base64url..."
  },
  "encryption": {
    "alg": "xchacha20-poly1305",
    "nonce": "base64url...",
    "aad": {
      "app": "umbra",
      "purpose": "vault_key_wrapping",
      "schema": 1,
      "vault_id": "...",
      "item_id": null,
      "revision": null,
      "kind": null
    },
    "ciphertext": "base64url..."
  }
}
```

## Required Tests

- Decryption fails when AAD changes.
- Decryption fails when nonce changes.
- Decryption fails when ciphertext changes.
- Same password with different salts derives different keys.
- KDF params serialize and deserialize.
- User private key wrap and unwrap works.
- Vault key wrap and unwrap works.
- Item encrypt and decrypt works.

## Implemented Public API

```txt
generate_user_keypair()
derive_account_kek(password, secret_key, params)
encrypt_user_private_key(account_kek, private_key, aad)
decrypt_user_private_key(account_kek, expected_aad, envelope)
generate_vault_key()
wrap_vault_key_for_user(public_key, vault_key, aad)
unwrap_vault_key(private_key, expected_aad, envelope)
encrypt_item(vault_key, aad, plaintext)
decrypt_item(vault_key, expected_aad, envelope)
```
