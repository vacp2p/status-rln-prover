use alloy::primitives::Address;
use ark_bn254::Fr;
use dashmap::DashMap;
use dashmap::mapref::one::Ref;
use rln::protocol::keygen;

#[derive(Debug)]
pub(crate) struct UserRegistry {
    inner: DashMap<Address, (Fr, Fr)>,
}

impl UserRegistry {
    fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    pub(crate) fn get(&self, address: &Address) -> Option<Ref<Address, (Fr, Fr)>> {
        self.inner.get(address)
    }

    fn register(&self, address: Address) {
        let (identity_secret_hash, id_commitment) = keygen();
        self.inner
            .insert(address, (identity_secret_hash, id_commitment));
    }
}

impl Default for UserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_user_registration() {
        let address = address!("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f");
        let reg = UserRegistry::default();
        reg.register(address);

        assert!(reg.get(&address).is_some());
    }
}
