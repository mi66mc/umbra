use sha2::{Digest, Sha384};
use std::{env, fs, path::Path};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR");
    let output =
        Path::new(&env::var("OUT_DIR").expect("Cargo sets OUT_DIR")).join("embedded_migrations.rs");
    let postgres = migrations(&manifest_dir, "migrations");
    let sqlite = migrations(&manifest_dir, "sqlite");

    fs::write(
        output,
        format!(
            "pub static POSTGRES_MIGRATOR: Migrator = Migrator {{ migrations: Cow::Borrowed(&[{postgres}]), ..Migrator::DEFAULT }};\n\
             pub static SQLITE_MIGRATOR: Migrator = Migrator {{ migrations: Cow::Borrowed(&[{sqlite}]), ..Migrator::DEFAULT }};\n\
             pub static MIGRATOR: &Migrator = &POSTGRES_MIGRATOR;\n"
        ),
    )
    .expect("write generated embedded migrations");
}

fn migrations(manifest_dir: &str, directory: &str) -> String {
    let path = Path::new(manifest_dir).join(directory);
    println!("cargo:rerun-if-changed={}", path.display());
    let mut files = fs::read_dir(&path)
        .expect("read migration directory")
        .map(|entry| entry.expect("read migration entry"))
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "sql")
        })
        .collect::<Vec<_>>();
    files.sort_by_key(|entry| entry.file_name());

    files
        .into_iter()
        .map(|entry| {
            println!("cargo:rerun-if-changed={}", entry.path().display());
            migration(
                directory,
                &entry.file_name().to_string_lossy(),
                &entry.path(),
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn migration(directory: &str, filename: &str, path: &Path) -> String {
    let (version, description) = filename
        .strip_suffix(".sql")
        .and_then(|filename| filename.split_once('_'))
        .expect("migration filename has version and description");
    let version: i64 = version.parse().expect("migration version is an integer");
    let sql = fs::read_to_string(path).expect("read migration SQL");
    let checksum = Sha384::digest(sql.as_bytes())
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let description = description.replace('_', " ");
    let no_tx = sql.starts_with("-- no-transaction");

    format!(
        "Migration {{ version: {version}, description: Cow::Borrowed({description:?}), migration_type: MigrationType::Simple, sql: Cow::Borrowed(include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{directory}/{filename}\"))), no_tx: {no_tx}, checksum: Cow::Borrowed(&[{checksum}]) }}"
    )
}
