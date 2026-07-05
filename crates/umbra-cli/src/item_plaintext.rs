#![allow(dead_code)]

use umbra_core::{ItemField, ItemFieldKind, ItemKind, ItemPlaintextV1};

pub fn default_fields_for_kind(kind: &ItemKind) -> Vec<&'static str> {
    match kind {
        ItemKind::Login => vec!["username", "password", "url"],
        ItemKind::SecureNote => Vec::new(),
        ItemKind::SshKey => vec!["private_key", "public_key", "passphrase"],
        ItemKind::ApiKey => vec!["key"],
        ItemKind::Token => vec!["token"],
        ItemKind::EnvVar => vec!["value"],
        ItemKind::EnvBundle => Vec::new(),
        ItemKind::CreditCard => vec!["number", "holder", "expires", "cvv"],
        ItemKind::Custom(_) => Vec::new(),
    }
}

pub fn field_kind_for_name(name: &str) -> ItemFieldKind {
    match name.to_ascii_lowercase().as_str() {
        "username" => ItemFieldKind::Username,
        "password" | "passphrase" | "cvv" => ItemFieldKind::Password,
        "url" => ItemFieldKind::Url,
        "token" | "access_token" => ItemFieldKind::Token,
        "key" | "private_key" | "api_key" | "secret" | "database_url" | "redis_url"
        | "openai_api_key" => ItemFieldKind::Secret,
        _ => ItemFieldKind::Text,
    }
}

pub fn is_sensitive_field(name: &str, kind: &ItemFieldKind) -> bool {
    matches!(
        kind,
        ItemFieldKind::Password
            | ItemFieldKind::Token
            | ItemFieldKind::Secret
            | ItemFieldKind::Totp
            | ItemFieldKind::CreditCardNumber
    ) || {
        let normalized = name.to_ascii_lowercase();
        normalized == "key"
            || normalized == "secret"
            || normalized == "token"
            || normalized == "password"
            || normalized == "passphrase"
            || normalized == "cvv"
            || normalized == "private_key"
            || normalized == "api_key"
            || normalized == "access_token"
            || normalized == "database_url"
            || normalized.contains("key")
            || normalized.contains("secret")
            || normalized.contains("token")
    }
}

pub fn build_item(
    title: &str,
    fields: Vec<(String, String)>,
    notes: Option<String>,
    tags: Vec<String>,
) -> ItemPlaintextV1 {
    let mut item = ItemPlaintextV1::new(title);
    item.notes = notes;
    item.tags = tags;
    item.fields = fields
        .into_iter()
        .map(|(name, value)| {
            let kind = field_kind_for_name(&name);
            let sensitive = is_sensitive_field(&name, &kind);
            ItemField::new(name, kind, value, sensitive)
        })
        .collect();
    item
}

pub fn build_secret_bundle(project_env: &str, key: &str, value: &str) -> ItemPlaintextV1 {
    let mut tags = vec!["env".to_owned()];
    if let Some((project, env)) = project_env.split_once('/') {
        tags.push(project.to_owned());
        tags.push(env.to_owned());
    }

    build_item(
        project_env,
        vec![(key.to_owned(), value.to_owned())],
        None,
        tags,
    )
}

pub fn set_plaintext_field(item: &mut ItemPlaintextV1, name: &str, value: String) {
    let kind = field_kind_for_name(name);
    let sensitive = is_sensitive_field(name, &kind);
    if let Some(field) = item.fields.iter_mut().find(|field| field.name == name) {
        field.kind = kind;
        field.value = value;
        field.sensitive = sensitive;
    } else {
        item.fields
            .push(ItemField::new(name.to_owned(), kind, value, sensitive));
    }
}

pub fn remove_plaintext_field(item: &mut ItemPlaintextV1, name: &str) -> bool {
    let before = item.fields.len();
    item.fields.retain(|field| field.name != name);
    item.fields.len() != before
}

pub fn env_pairs(item: &ItemPlaintextV1) -> Vec<(String, String)> {
    let mut pairs = item
        .fields
        .iter()
        .filter(|field| is_valid_env_name(&field.name))
        .map(|field| (field.name.clone(), field.value.clone()))
        .collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    pairs
}

pub fn render_dotenv(item: &ItemPlaintextV1) -> String {
    env_pairs(item)
        .into_iter()
        .map(|(name, value)| format!("{name}={}\n", quote_dotenv_value(&value)))
        .collect()
}

fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_uppercase()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_uppercase() || ch.is_ascii_digit())
}

fn quote_dotenv_value(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':' | '@'))
    {
        return value.to_owned();
    }

    let escaped = value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_env_bundle_with_secret_field() {
        let item = build_secret_bundle("umbra/prod", "OPENAI_API_KEY", "secret");

        assert_eq!(item.title, "umbra/prod");
        assert_eq!(item.tags, vec!["env", "umbra", "prod"]);
        assert_eq!(item.fields.len(), 1);
        assert_eq!(item.fields[0].name, "OPENAI_API_KEY");
        assert_eq!(item.fields[0].kind, ItemFieldKind::Secret);
        assert_eq!(item.fields[0].value, "secret");
        assert!(item.fields[0].sensitive);
    }

    #[test]
    fn marks_lowercase_secret_fields_sensitive() {
        let item = build_item(
            "x",
            vec![
                ("api_key".to_owned(), "v".to_owned()),
                ("access_token".to_owned(), "v".to_owned()),
                ("secret".to_owned(), "v".to_owned()),
            ],
            None,
            vec![],
        );

        assert!(item.fields.iter().all(|field| field.sensitive));
        assert_eq!(item.fields[0].kind, ItemFieldKind::Secret);
        assert_eq!(item.fields[1].kind, ItemFieldKind::Token);
        assert_eq!(item.fields[2].kind, ItemFieldKind::Secret);
    }

    #[test]
    fn default_fields_for_login() {
        assert_eq!(
            default_fields_for_kind(&ItemKind::Login),
            vec!["username", "password", "url"]
        );
    }

    #[test]
    fn set_plaintext_field_updates_or_inserts() {
        let mut item = build_secret_bundle("umbra/prod", "DATABASE_URL", "old");

        set_plaintext_field(&mut item, "DATABASE_URL", "new".to_owned());
        set_plaintext_field(&mut item, "OPENAI_API_KEY", "secret".to_owned());

        assert_eq!(item.fields.len(), 2);
        assert_eq!(item.fields[0].value, "new");
        assert_eq!(item.fields[1].name, "OPENAI_API_KEY");
        assert!(item.fields[1].sensitive);
    }

    #[test]
    fn remove_plaintext_field_removes_existing_field() {
        let mut item = build_secret_bundle("umbra/prod", "DATABASE_URL", "old");
        set_plaintext_field(&mut item, "OPENAI_API_KEY", "secret".to_owned());

        assert!(remove_plaintext_field(&mut item, "DATABASE_URL"));
        assert!(!remove_plaintext_field(&mut item, "MISSING"));
        assert_eq!(item.fields.len(), 1);
        assert_eq!(item.fields[0].name, "OPENAI_API_KEY");
    }

    #[test]
    fn env_pairs_are_sorted_by_key() {
        let mut item = build_secret_bundle("pulzar/dev", "DATABASE_URL", "postgres://localhost");
        set_plaintext_field(&mut item, "OPENAI_API_KEY", "sk-test".to_owned());
        set_plaintext_field(&mut item, "REDIS_URL", "redis://localhost".to_owned());

        let pairs = env_pairs(&item);

        assert_eq!(
            pairs,
            vec![
                ("DATABASE_URL".to_owned(), "postgres://localhost".to_owned()),
                ("OPENAI_API_KEY".to_owned(), "sk-test".to_owned()),
                ("REDIS_URL".to_owned(), "redis://localhost".to_owned()),
            ]
        );
    }

    #[test]
    fn dotenv_output_quotes_values_safely() {
        let mut item = build_secret_bundle("pulzar/dev", "DATABASE_URL", "postgres://localhost/db");
        set_plaintext_field(&mut item, "PLAIN", "abc_123".to_owned());
        set_plaintext_field(&mut item, "SPACED", "hello world".to_owned());
        set_plaintext_field(&mut item, "QUOTE", "a\"b".to_owned());
        set_plaintext_field(&mut item, "MULTILINE", "a\nb".to_owned());

        let rendered = render_dotenv(&item);

        assert_eq!(
            rendered,
            "DATABASE_URL=postgres://localhost/db\nMULTILINE=\"a\\nb\"\nPLAIN=abc_123\nQUOTE=\"a\\\"b\"\nSPACED=\"hello world\"\n"
        );
    }

    #[test]
    fn invalid_env_names_are_omitted_from_dotenv_output() {
        let mut item = build_secret_bundle("pulzar/dev", "VALID_KEY", "ok");
        set_plaintext_field(&mut item, "not-valid", "bad".to_owned());
        set_plaintext_field(&mut item, "1INVALID", "bad".to_owned());

        let rendered = render_dotenv(&item);

        assert_eq!(rendered, "VALID_KEY=ok\n");
    }
}
