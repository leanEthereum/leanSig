use leansig::{
    MESSAGE_LENGTH,
    serialization::Serializable,
    signature::{SignatureScheme, SignatureSchemeSecretKey},
};
#[cfg(not(feature = "production-lifetime-18-w2"))]
use leansig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_10::target_sum::SIGTargetSumLifetime10W2NoOff as SelectedScheme;
#[cfg(feature = "production-lifetime-18-w2")]
use leansig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W2NoOff as SelectedScheme;
use rand::rng;
use wasm_bindgen::prelude::*;

type DemoScheme = SelectedScheme;
type DemoPublicKey = <DemoScheme as SignatureScheme>::PublicKey;
type DemoSecretKey = <DemoScheme as SignatureScheme>::SecretKey;
type DemoSignature = <DemoScheme as SignatureScheme>::Signature;

fn js_error(message: impl Into<String>) -> JsValue {
    JsValue::from_str(&message.into())
}

fn decode_message(message: &[u8]) -> Result<[u8; MESSAGE_LENGTH], JsValue> {
    message.try_into().map_err(|_| {
        js_error(format!(
            "expected {MESSAGE_LENGTH} message bytes, got {}",
            message.len()
        ))
    })
}

fn decode_public_key(bytes: &[u8]) -> Result<DemoPublicKey, JsValue> {
    DemoPublicKey::from_bytes(bytes)
        .map_err(|err| js_error(format!("invalid public key bytes: {err:?}")))
}

fn decode_signature(bytes: &[u8]) -> Result<DemoSignature, JsValue> {
    DemoSignature::from_bytes(bytes)
        .map_err(|err| js_error(format!("invalid signature bytes: {err:?}")))
}

#[wasm_bindgen]
pub fn demo_message_length() -> usize {
    MESSAGE_LENGTH
}

#[wasm_bindgen]
pub fn demo_lifetime() -> u32 {
    DemoScheme::LIFETIME as u32
}

#[wasm_bindgen]
pub fn demo_scheme_name() -> String {
    #[cfg(feature = "production-lifetime-18-w2")]
    {
        "Poseidon target-sum, lifetime 2^18, w=2, no offset".to_string()
    }

    #[cfg(not(feature = "production-lifetime-18-w2"))]
    {
        "Poseidon target-sum, lifetime 2^10, w=2, no offset".to_string()
    }
}

#[wasm_bindgen]
pub fn verify_demo_signature(
    public_key_bytes: &[u8],
    epoch: u32,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, JsValue> {
    let public_key = decode_public_key(public_key_bytes)?;
    let signature = decode_signature(signature_bytes)?;
    let message = decode_message(message)?;

    Ok(DemoScheme::verify(&public_key, epoch, &message, &signature))
}

#[wasm_bindgen]
pub struct DemoKeypair {
    secret_key: DemoSecretKey,
    public_key: DemoPublicKey,
}

#[wasm_bindgen]
impl DemoKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new(secret_key_bytes: &[u8]) -> Result<DemoKeypair, JsValue> {
        let secret_key = DemoSecretKey::from_bytes(secret_key_bytes)
            .map_err(|err| js_error(format!("invalid secret key bytes: {err:?}")))?;
        let public_key = DemoScheme::get_public_key(&secret_key);

        Ok(Self {
            secret_key,
            public_key,
        })
    }

    #[wasm_bindgen(js_name = generate)]
    pub fn generate() -> DemoKeypair {
        let mut rng = rng();
        let (public_key, secret_key) =
            DemoScheme::key_gen(&mut rng, 0, DemoScheme::LIFETIME as usize);

        Self {
            secret_key,
            public_key,
        }
    }

    #[wasm_bindgen(js_name = publicKeyBytes)]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes()
    }

    #[wasm_bindgen(js_name = secretKeyBytes)]
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.to_bytes()
    }

    #[wasm_bindgen(js_name = activationIntervalStart)]
    pub fn activation_interval_start(&self) -> u32 {
        self.secret_key.get_activation_interval().start as u32
    }

    #[wasm_bindgen(js_name = activationIntervalEnd)]
    pub fn activation_interval_end(&self) -> u32 {
        self.secret_key.get_activation_interval().end as u32
    }

    #[wasm_bindgen(js_name = preparedIntervalStart)]
    pub fn prepared_interval_start(&self) -> u32 {
        self.secret_key.get_prepared_interval().start as u32
    }

    #[wasm_bindgen(js_name = preparedIntervalEnd)]
    pub fn prepared_interval_end(&self) -> u32 {
        self.secret_key.get_prepared_interval().end as u32
    }

    #[wasm_bindgen(js_name = advancePreparation)]
    pub fn advance_preparation(&mut self) {
        self.secret_key.advance_preparation();
    }

    pub fn sign(&self, epoch: u32, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let message = decode_message(message)?;
        let signature = DemoScheme::sign(&self.secret_key, epoch, &message)
            .map_err(|err| js_error(format!("signing failed: {err}")))?;

        Ok(signature.to_bytes())
    }

    pub fn verify(
        &self,
        epoch: u32,
        message: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, JsValue> {
        let message = decode_message(message)?;
        let signature = decode_signature(signature_bytes)?;

        Ok(DemoScheme::verify(
            &self.public_key,
            epoch,
            &message,
            &signature,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_keypair_roundtrip_sign_verify() {
        let mut keypair = DemoKeypair::generate();
        let message = [7u8; MESSAGE_LENGTH];
        let epoch = keypair.prepared_interval_start();

        let signature_bytes = keypair.sign(epoch, &message).unwrap();
        assert!(keypair.verify(epoch, &message, &signature_bytes).unwrap());
        assert!(
            verify_demo_signature(
                &keypair.public_key_bytes(),
                epoch,
                &message,
                &signature_bytes,
            )
            .unwrap()
        );

        let secret_key_bytes = keypair.secret_key_bytes();
        let imported = DemoKeypair::new(&secret_key_bytes).unwrap();
        assert_eq!(imported.public_key_bytes(), keypair.public_key_bytes());
        assert!(imported.verify(epoch, &message, &signature_bytes).unwrap());

        let prepared_before = keypair.prepared_interval_start();
        keypair.advance_preparation();
        assert!(keypair.prepared_interval_start() >= prepared_before);
    }
}
