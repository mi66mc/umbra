# Migration compatibility and rollback

Database migrations are forward-only. Every migration must have PostgreSQL and SQLite implementations, preserve encrypted-envelope boundaries, and be tested from the prior released schema. No migration may introduce plaintext secrets, plaintext vault keys, master passwords, or decrypted item fields.

Use expand/contract changes: add compatible structures first, deploy code that can read both shapes, migrate data, and remove legacy structures only in a later release. The release test matrix must prove server N can migrate schema N-1 and server N-1 can start against schema N when rollback is documented as supported.

Rollback is application rollback, not SQL downgrade: stop rollout, restore the preceding compatible server image, and validate `/health`, `/ready`, `migrate status`, and `doctor --strict`. If schema incompatibility or data corruption is suspected, restore a verified pre-migration backup into an isolated database before promotion. Never use automatic destructive SQL rollback.
