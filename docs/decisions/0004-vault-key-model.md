# 0004: Vault Key Model

## Decision

Each vault has a random vault key. Each authorized user/device receives a wrapped copy of that vault key.

```txt
vault_key = random 32 bytes
wrapped_for_user = encrypt(user_public_key, vault_key)
```

## Consequences

- A user can have multiple vaults.
- A vault can have multiple members.
- Removing a member can stop future sync immediately.
- Full cryptographic removal requires vault key rotation and real-world secret rotation.
