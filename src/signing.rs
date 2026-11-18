//! OpenPGP signing of repository metadata (APT InRelease/Release.gpg, RPM repomd.xml.asc,
//! pacman .db.sig), implemented in pure Rust with rPGP.

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use pgp::composed::{
    ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, EncryptionCaps,
    KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::ser::Serialize;
use pgp::types::{KeyDetails, Password, SigningKey};

pub struct Signer {
    secret: SignedSecretKey,
    password: Password,
    public: SignedPublicKey,
    public_armored: String,
}

impl Signer {
    pub fn from_file(path: &Path, passphrase: Option<&str>) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading signing key {}", path.display()))?;
        Self::from_armored(&raw, passphrase)
    }

    pub fn from_armored(armored: &str, passphrase: Option<&str>) -> Result<Self> {
        let (secret, _) = SignedSecretKey::from_string(armored)
            .map_err(|e| anyhow!("parsing OpenPGP secret key: {e}"))?;
        let password = passphrase.map(Password::from).unwrap_or_default();
        let public = SignedPublicKey::from(secret.clone());
        let public_armored = public
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| anyhow!("armoring public key: {e}"))?;
        let signer = Self {
            secret,
            password,
            public,
            public_armored,
        };
        // Fail fast on a wrong passphrase instead of on the first request.
        signer
            .detached_binary(b"self-test")
            .context("signing key self-test failed (wrong passphrase?)")?;
        Ok(signer)
    }

    pub fn fingerprint(&self) -> String {
        hex::encode_upper(self.secret.primary_key.fingerprint().as_bytes())
    }

    pub fn public_key_armored(&self) -> &str {
        &self.public_armored
    }

    pub fn public_key_binary(&self) -> Result<Vec<u8>> {
        self.public
            .to_bytes()
            .map_err(|e| anyhow!("serialize public key: {e}"))
    }

    /// Prefer a signing-capable subkey (as GnuPG does); fall back to the primary key.
    fn signing_key(&self) -> &dyn SigningKey {
        for sub in &self.secret.secret_subkeys {
            if sub.signatures.iter().any(|s| s.key_flags().sign()) {
                return &sub.key;
            }
        }
        &self.secret.primary_key
    }

    /// Cleartext-signed message (APT `InRelease`).
    pub fn clearsign(&self, text: &str) -> Result<String> {
        let key = Box::new(self.signing_key());
        let msg = CleartextSignedMessage::sign(rand::thread_rng(), text, &key, &self.password)
            .map_err(|e| anyhow!("clearsign: {e}"))?;
        msg.to_armored_string(ArmorOptions::default())
            .map_err(|e| anyhow!("armor: {e}"))
    }

    fn detached(&self, data: &[u8]) -> Result<DetachedSignature> {
        let key = Box::new(self.signing_key());
        DetachedSignature::sign_binary_data(
            rand::thread_rng(),
            &key,
            &self.password,
            HashAlgorithm::Sha256,
            data,
        )
        .map_err(|e| anyhow!("sign: {e}"))
    }

    /// ASCII-armored detached signature (`Release.gpg`, `repomd.xml.asc`).
    pub fn detached_armored(&self, data: &[u8]) -> Result<String> {
        self.detached(data)?
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| anyhow!("armor: {e}"))
    }

    /// Binary detached signature (pacman `.db.sig`).
    pub fn detached_binary(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Serialize the DetachedSignature (with packet framing), not the bare Signature body.
        self.detached(data)?
            .to_bytes()
            .map_err(|e| anyhow!("serialize: {e}"))
    }
}

/// Generate a new Ed25519 signing key; returns (armored secret key, armored public key).
pub fn generate(user_id: &str) -> Result<(String, String)> {
    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id(user_id.into())
        .build()
        .map_err(|e| anyhow!("key params: {e}"))?;
    let secret = params
        .generate(rand::thread_rng())
        .map_err(|e| anyhow!("keygen: {e}"))?;
    let public = SignedPublicKey::from(secret.clone());
    Ok((
        secret
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| anyhow!("{e}"))?,
        public
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| anyhow!("{e}"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let (sec, pubk) = generate("Test <test@example.invalid>").unwrap();
        assert!(pubk.contains("BEGIN PGP PUBLIC KEY BLOCK"));
        let s = Signer::from_armored(&sec, None).unwrap();
        let signed = s.clearsign("Origin: test\nSuite: stable\n").unwrap();
        assert!(signed.starts_with("-----BEGIN PGP SIGNED MESSAGE-----"));
        let (msg, _) = CleartextSignedMessage::from_string(&signed).unwrap();
        let (public, _) = SignedPublicKey::from_string(s.public_key_armored()).unwrap();
        msg.verify(&public).unwrap();
        assert!(
            s.detached_armored(b"x")
                .unwrap()
                .contains("BEGIN PGP SIGNATURE")
        );

        // Binary signatures (pacman .db.sig) must be complete OpenPGP packets.
        let bin = s.detached_binary(b"payload").unwrap();
        let sig = DetachedSignature::from_bytes(&bin[..]).unwrap();
        sig.verify(&public, &b"payload"[..]).unwrap();
        assert!(sig.verify(&public, &b"tampered"[..]).is_err());
    }
}
