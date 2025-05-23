// std
use std::io::Cursor;
// third-party
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use rln::circuit::ZKEY_BYTES;
use rln::circuit::zkey::read_zkey;
use rln::hashers::{hash_to_field, poseidon_hash};
use rln::protocol::{
    ProofError, RLNProofValues, generate_proof, proof_values_from_witness, rln_witness_from_values,
};

/// A RLN user identity & limit
#[derive(Debug, Clone)]
pub struct RlnUserIdentity {
    pub commitment: Fr,
    pub secret_hash: Fr,
    pub user_limit: Fr,
}

impl From<(Fr, Fr)> for RlnUserIdentity {
    fn from((commitment, secret_hash): (Fr, Fr)) -> Self {
        Self {
            commitment,
            secret_hash,
            user_limit: Fr::from(0),
        }
    }
}

/// RLN info for a channel / group
#[derive(Debug, Clone)]
pub struct RlnIdentifier {
    pub identifier: Fr,
    pub pkey_and_constraints: (ProvingKey<Bn254>, ConstraintMatrices<Fr>),
    pub graph: Vec<u8>,
}

impl RlnIdentifier {
    pub fn new(identifier: &[u8]) -> Self {
        // TODO: valid / correct ?
        let pk_and_matrices = {
            let mut reader = Cursor::new(ZKEY_BYTES);
            read_zkey(&mut reader).unwrap()
        };
        let graph_bytes = include_bytes!("../resources/graph.bin");

        Self {
            identifier: hash_to_field(identifier),
            pkey_and_constraints: pk_and_matrices,
            graph: graph_bytes.to_vec(),
        }
    }
}

/// Data to be proven by RLN
#[derive(Debug, Clone)]
pub struct RlnData {
    /// message index (in a given epoch)
    pub message_id: Fr,
    /// message / signal hashed (bytes hashed to a field element type)
    pub data: Fr,
}

pub fn compute_rln_proof_and_values(
    user_identity: &RlnUserIdentity,
    rln_identifier: &RlnIdentifier,
    rln_data: RlnData,
    epoch: Fr,
    merkle_proof: &rln::poseidon_tree::MerkleProof,
) -> Result<(Proof<Bn254>, RLNProofValues), ProofError> {
    let external_nullifier = poseidon_hash(&[rln_identifier.identifier, epoch]);

    let witness = rln_witness_from_values(
        user_identity.secret_hash,
        merkle_proof,
        rln_data.data,
        external_nullifier,
        user_identity.user_limit,
        rln_data.message_id,
    )?;

    let proof_values = proof_values_from_witness(&witness)?;
    let proof = generate_proof(
        &rln_identifier.pkey_and_constraints,
        &witness,
        rln_identifier.graph.as_slice(),
    )?;
    Ok((proof, proof_values))
}
