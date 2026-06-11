#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStatus {
    Unknown,
    Clean,
    Pending,
}

pub fn migration_status_placeholder() -> MigrationStatus {
    MigrationStatus::Unknown
}
