use base64ct::{Base64UrlUnpadded, Encoding};
use opaque_ke::ServerSetup;
use opaque_ke::rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::{Digest, Sha256};

use crate::config::AppConfig;
use crate::error::ServerError;
use crate::state::OpaqueCipherSuite;
use umbra_protocol::PROTOCOL_VERSION;

pub(crate) fn ensure_protocol(version: u16) -> Result<(), ServerError> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ServerError::BadRequest("unsupported protocol version"))
    }
}

pub(crate) fn encode_b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

pub(crate) fn decode_b64(value: &str) -> Result<Vec<u8>, ServerError> {
    Base64UrlUnpadded::decode_vec(value).map_err(|_| ServerError::BadRequest("invalid base64url"))
}

pub(crate) fn token_hash(token: &str) -> String {
    encode_b64(&Sha256::digest(token.as_bytes()))
}

pub(crate) fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    encode_b64(&bytes)
}

pub(crate) fn generate_opaque_server_setup_secret() -> String {
    let setup = ServerSetup::<OpaqueCipherSuite>::new(&mut OsRng);
    encode_b64(setup.serialize().as_slice())
}

pub(crate) fn opaque_server_setup_from_config(
    config: &AppConfig,
) -> Result<ServerSetup<OpaqueCipherSuite>, ServerError> {
    if let Some(secret) = &config.auth.opaque.server_setup {
        return opaque_server_setup_from_secret(secret);
    }

    if config.auth.opaque.allow_ephemeral_setup {
        return Ok(ServerSetup::<OpaqueCipherSuite>::new(&mut OsRng));
    }

    Err(ServerError::MissingOpaqueServerSetup)
}

pub(crate) fn opaque_server_setup_from_secret(
    secret: &str,
) -> Result<ServerSetup<OpaqueCipherSuite>, ServerError> {
    let bytes = decode_b64(secret)?;
    ServerSetup::<OpaqueCipherSuite>::deserialize(&bytes)
        .map_err(|_| ServerError::BadRequest("invalid opaque server setup"))
}
