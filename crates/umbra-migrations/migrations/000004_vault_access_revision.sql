ALTER TABLE vaults
    ADD COLUMN access_revision bigint NOT NULL DEFAULT 0 CHECK (access_revision >= 0);

CREATE INDEX vaults_access_revision_idx
    ON vaults(id, access_revision);
