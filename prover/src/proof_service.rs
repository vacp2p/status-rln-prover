use std::env;
use std::io::{Cursor, Write};
use std::str::FromStr;
use std::sync::Arc;
// third-party
use ark_bn254::Fr;
use ark_serialize::CanonicalSerialize;
use async_channel::Receiver;
use metrics::{counter, histogram};
#[cfg(target_os = "linux")]
use nix::{
    sched::{CpuSet, sched_setaffinity},
    unistd::Pid,
};
use parking_lot::RwLock;
use rln::hashers::hash_to_field_le;
use rln::protocol::serialize_proof_values;
use tracing::{
    Instrument, // debug,
    debug_span,
    info,
};
// internal
use crate::epoch_service::{Epoch, EpochSlice};
use crate::error::{AppError, ProofGenerationError, ProofGenerationStringError};
use crate::metrics::{
    BROADCAST_CHANNEL_QUEUE_LEN, PROOF_SERVICE_GEN_PROOF_TIME, PROOF_SERVICE_PROOF_COMPUTED,
};
use crate::proof_generation::{ProofGenerationData, ProofSendingData};
use crate::user_db::UserDb;
use crate::user_db_types::RateLimit;
use rln_proof::{RlnData, compute_rln_proof_and_values};

const PROOF_SIZE: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinningStrategy {
    None,
    Numa,
    Even,
    Physical,
}

impl FromStr for PinningStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(PinningStrategy::None),
            "numa" => Ok(PinningStrategy::Numa),
            "even" => Ok(PinningStrategy::Even),
            "physical" => Ok(PinningStrategy::Physical),
            _ => Err(format!(
                "Unknown pinning strategy: '{}'. Valid options: none, numa, even, physical",
                s
            )),
        }
    }
}

/// Setup pinned global Rayon thread pool - call this before creating any ProofService
pub fn setup_pinned_rayon_pool() {
    let default_threads = num_cpus::get();
    let num_threads = std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default_threads);

    let pinning_strategy = env::var("CPU_PINNING_STRATEGY")
        .unwrap_or_else(|_| "none".to_string())
        .parse::<PinningStrategy>()
        .unwrap_or(PinningStrategy::None);

    println!(
        "Setting up global Rayon thread pool with {num_threads} threads and '{pinning_strategy:?}' CPU pinning strategy"
    );

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .thread_name(|index| format!("rayon-pinned-{}", index))
        .start_handler(move |thread_index| {
            apply_cpu_pinning(thread_index, pinning_strategy);
        })
        .build_global()
        .expect("Failed to build global rayon thread pool");
}

fn apply_cpu_pinning(thread_index: usize, strategy: PinningStrategy) {
    #[cfg(target_os = "linux")]
    {
        match strategy {
            PinningStrategy::None => {}
            PinningStrategy::Numa => pin_numa(thread_index),
            PinningStrategy::Even => pin_even(thread_index),
            PinningStrategy::Physical => pin_physical(thread_index),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (thread_index, strategy);
    }
}

#[cfg(target_os = "linux")]
fn detect_numa_topology() -> (usize, Vec<usize>) {
    // Try to read actual NUMA topology
    let numa_nodes = std::fs::read_dir("/sys/devices/system/node/")
        .map(|entries| {
            entries
                .filter_map(|entry| {
                    entry.ok().and_then(|e| {
                        e.file_name().to_str().and_then(|name| {
                            if name.starts_with("node") {
                                name[4..].parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                    })
                })
                .max()
                .map(|max_node| max_node + 1)
                .unwrap_or(1)
        })
        .unwrap_or(1);

    // Try to get cores per NUMA node from /proc/cpuinfo or sysfs
    // For now, assume even distribution as fallback
    let physical_cores = num_cpus::get_physical();
    let cores_per_numa = physical_cores / numa_nodes;
    let mut numa_core_counts = vec![cores_per_numa; numa_nodes];

    // Handle remainder cores
    let remainder = physical_cores % numa_nodes;
    for i in 0..remainder {
        numa_core_counts[i] += 1;
    }

    (numa_nodes, numa_core_counts)
}

#[cfg(target_os = "linux")]
fn pin_numa(thread_index: usize) {
    let (numa_nodes, numa_core_counts) = detect_numa_topology();
    let physical_cores = num_cpus::get_physical();
    let logical_cores = num_cpus::get();

    // Find which NUMA node this thread should be on
    let mut cumulative_cores = 0;
    let mut target_numa = 0;
    let mut core_in_numa = thread_index;

    for (numa_id, &cores_in_this_numa) in numa_core_counts.iter().enumerate() {
        if thread_index < cumulative_cores + cores_in_this_numa {
            target_numa = numa_id;
            core_in_numa = thread_index - cumulative_cores;
            break;
        }
        cumulative_cores += cores_in_this_numa;
    }

    // Calculate actual core assignment
    let numa_start_core: usize = numa_core_counts[..target_numa].iter().sum();
    let assigned_core = numa_start_core + core_in_numa;

    if assigned_core >= physical_cores {
        return; // Invalid core assignment
    }

    let mut cpu_set = CpuSet::new();

    // Always pin to physical core
    if cpu_set.set(assigned_core).is_err() {
        return;
    }

    // Try to add hyperthreaded sibling if it exists
    let ht_sibling = assigned_core + physical_cores;
    if ht_sibling < logical_cores {
        let _ = cpu_set.set(ht_sibling);
    }

    let _ = sched_setaffinity(Pid::from_raw(0), &cpu_set);
}

#[cfg(target_os = "linux")]
fn pin_even(thread_index: usize) {
    let physical_cores = num_cpus::get_physical();
    let logical_cores = num_cpus::get();

    // Get strategy variant from environment
    let even_strategy =
        std::env::var("CPU_PINNING_EVEN_STRATEGY").unwrap_or_else(|_| "round_robin".to_string());

    println!(
        "Using even CPU pinning strategy variant: '{}'",
        even_strategy
    );

    let assigned_core = match even_strategy.as_str() {
        "physical_first" => pin_even_physical_first(thread_index, physical_cores, logical_cores),
        "interleaved" => pin_even_interleaved(thread_index, physical_cores, logical_cores),
        "numa_even" => pin_even_numa_aware(thread_index, physical_cores, logical_cores),
        _ => thread_index % logical_cores, // Default round-robin
    };

    let mut cpu_set = CpuSet::new();
    if cpu_set.set(assigned_core).is_ok() {
        let _ = sched_setaffinity(Pid::from_raw(0), &cpu_set);
    }
}

#[cfg(target_os = "linux")]
fn pin_even_physical_first(
    thread_index: usize,
    physical_cores: usize,
    logical_cores: usize,
) -> usize {
    // Use physical cores first (0-31), then hyperthreaded siblings (32-63)
    if thread_index < physical_cores {
        thread_index // Physical cores first
    } else {
        physical_cores + (thread_index - physical_cores) // Then logical cores
    }
}

#[cfg(target_os = "linux")]
fn pin_even_interleaved(
    thread_index: usize,
    physical_cores: usize,
    _logical_cores: usize,
) -> usize {
    // Interleave: 0,32,1,33,2,34... to spread heat and execution units
    let physical_core = thread_index / 2;
    let is_hyperthreaded = thread_index % 2;

    if is_hyperthreaded == 0 {
        physical_core % physical_cores // Physical core
    } else {
        (physical_core % physical_cores) + physical_cores // HT sibling
    }
}

#[cfg(target_os = "linux")]
fn pin_even_numa_aware(thread_index: usize, physical_cores: usize, logical_cores: usize) -> usize {
    // Even distribution but respect NUMA boundaries
    let (numa_nodes, _) = detect_numa_topology();
    let cores_per_numa = logical_cores / numa_nodes;

    let numa_node = (thread_index / cores_per_numa) % numa_nodes;
    let core_in_numa = thread_index % cores_per_numa;
    let numa_start = numa_node * cores_per_numa;

    numa_start + core_in_numa
}

#[cfg(target_os = "linux")]
fn pin_physical(thread_index: usize) {
    let physical_cores = num_cpus::get_physical();
    let assigned_core = thread_index % physical_cores;

    let mut cpu_set = CpuSet::new();
    if cpu_set.set(assigned_core).is_ok() {
        let _ = sched_setaffinity(Pid::from_raw(0), &cpu_set);
    }
}

/// A service to generate a RLN proof (and then to broadcast it)
pub struct ProofService {
    receiver: Receiver<ProofGenerationData>,
    broadcast_sender:
        tokio::sync::broadcast::Sender<Result<ProofSendingData, ProofGenerationStringError>>,
    current_epoch: Arc<RwLock<(Epoch, EpochSlice)>>,
    user_db: UserDb,
    rate_limit: RateLimit,
    id: u64,
}

impl ProofService {
    pub(crate) fn new(
        receiver: Receiver<ProofGenerationData>,
        broadcast_sender: tokio::sync::broadcast::Sender<
            Result<ProofSendingData, ProofGenerationStringError>,
        >,
        current_epoch: Arc<RwLock<(Epoch, EpochSlice)>>,
        user_db: UserDb,
        rate_limit: RateLimit,
        id: u64,
    ) -> Self {
        debug_assert!(rate_limit > RateLimit::ZERO);
        Self {
            receiver,
            broadcast_sender,
            current_epoch,
            user_db,
            rate_limit,
            id,
        }
    }

    pub(crate) async fn serve(&self) -> Result<(), AppError> {
        loop {
            let received = self.receiver.recv().await;

            if let Err(e) = received {
                info!("Stopping proof generation service: {}", e);
                break;
            }

            let proof_generation_data = received.unwrap();

            let (current_epoch, current_epoch_slice) = *self.current_epoch.read();
            let user_db = self.user_db.clone();
            let proof_generation_data_ = proof_generation_data.clone();
            let rate_limit = self.rate_limit;

            let counter_id = self.id;
            // println!("[proof service {counter_id}] starting to generate proof...");

            // Communicate between rayon & current task
            let (send, recv) = tokio::sync::oneshot::channel();

            // Move to a task (as generating the proof can take quite some time) - avoid blocking the tokio runtime
            // Note: avoid tokio spawn_blocking as it does not perform great for CPU bounds tasks
            //       see https://ryhl.io/blog/async-what-is-blocking/

            rayon::spawn(move || {
                let proof_generation_start = std::time::Instant::now();

                let message_id = {
                    let mut m_id = proof_generation_data.tx_counter;
                    // Note: Zerokit can only recover user secret hash with 2 messages with the
                    //       same message_id so here we force to use the previous message_id
                    //       so the Verifier could recover the secret hash
                    if RateLimit::from(m_id) == rate_limit {
                        m_id -= 1;
                    }
                    m_id
                };

                let rln_data = RlnData {
                    message_id: Fr::from(message_id),
                    data: hash_to_field_le(proof_generation_data.tx_hash.as_slice()),
                };

                let epoch_bytes = {
                    let mut v = current_epoch.to_le_bytes().to_vec();
                    v.extend(current_epoch_slice.to_le_bytes());
                    v
                };
                let epoch = hash_to_field_le(epoch_bytes.as_slice());

                let merkle_proof = match user_db.get_merkle_proof(&proof_generation_data.tx_sender)
                {
                    Ok(merkle_proof) => merkle_proof,
                    Err(e) => {
                        let _ = send.send(Err(ProofGenerationError::MerkleProofError(e)));
                        return;
                    }
                };

                // let compute_proof_start = std::time::Instant::now();
                let (proof, proof_values) = match compute_rln_proof_and_values(
                    &proof_generation_data.user_identity,
                    &proof_generation_data.rln_identifier,
                    rln_data,
                    epoch,
                    &merkle_proof,
                ) {
                    Ok((proof, proof_values)) => (proof, proof_values),
                    Err(e) => {
                        let _ = send.send(Err(ProofGenerationError::Proof(e)));
                        return;
                    }
                };

                // debug!("proof: {:?}", proof);
                // debug!("proof_values: {:?}", proof_values);

                // Serialize proof
                let mut output_buffer = Cursor::new(Vec::with_capacity(PROOF_SIZE));
                if let Err(e) = proof.serialize_compressed(&mut output_buffer) {
                    let _ = send.send(Err(ProofGenerationError::Serialization(e)));
                    return;
                }
                if let Err(e) = output_buffer.write_all(&serialize_proof_values(&proof_values)) {
                    let _ = send.send(Err(ProofGenerationError::SerializationWrite(e)));
                    return;
                }

                histogram!(PROOF_SERVICE_GEN_PROOF_TIME.name, "prover" => "proof service")
                    .record(proof_generation_start.elapsed().as_secs_f64());
                // println!("[proof service {counter_id}] proof generation time: {:?} secs", proof_generation_start.elapsed().as_secs_f64());
                let labels = [("prover", format!("proof service id: {counter_id}"))];
                counter!(PROOF_SERVICE_PROOF_COMPUTED.name, &labels).increment(1);

                // Send the result back to Tokio.
                let _ = send.send(Ok::<Vec<u8>, ProofGenerationError>(
                    output_buffer.into_inner(),
                ));

                /*
                std::thread::sleep(std::time::Duration::from_millis(100));
                let mut output_buffer = Cursor::new(Vec::with_capacity(PROOF_SIZE));
                // Send the result back to Tokio.
                let _ = send.send(Ok::<Vec<u8>, ProofGenerationError>(
                    output_buffer.into_inner(),
                ));
                */
            });

            // Wait for the rayon task.
            // Result 1st is from send channel (no errors expected)
            // Result 2nd can be a ProofGenerationError
            let result = recv
                .instrument(debug_span!("compute proof"))
                .await
                .expect("Panic in rayon::spawn"); // Should never happen (but panic if it does)

            let proof_sending_data = result
                .map(|r| ProofSendingData {
                    tx_hash: proof_generation_data_.tx_hash,
                    tx_sender: proof_generation_data_.tx_sender,
                    proof: r,
                })
                .map_err(ProofGenerationStringError::from);

            if let Err(e) = self.broadcast_sender.send(proof_sending_data) {
                info!("Stopping proof generation service: {}", e);
                break;
            };

            // Note: based on this link https://doc.rust-lang.org/reference/expressions/operator-expr.html#type-cast-expressions
            //       "Casting from an integer to float will produce the closest possible float *"
            histogram!(BROADCAST_CHANNEL_QUEUE_LEN.name, "prover" => "proof service")
                .record(self.broadcast_sender.len() as f64);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // std
    use std::path::PathBuf;
    // third-party
    use alloy::primitives::{Address, address};
    use ark_groth16::{Proof as ArkProof, VerifyingKey};
    use ark_serialize::CanonicalDeserialize;
    use claims::assert_matches;
    use futures::TryFutureExt;
    use tokio::sync::broadcast;
    use tracing::{debug, info};
    // third-party: zerokit
    use rln::{
        circuit::{Curve, zkey_from_folder},
        protocol::{deserialize_proof_values, verify_proof},
    };
    // internal
    use crate::user_db_service::UserDbService;
    use rln_proof::RlnIdentifier;

    const ADDR_1: Address = address!("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
    const ADDR_2: Address = address!("0xb20a608c624Ca5003905aA834De7156C68b2E1d0");

    const TX_HASH_1: [u8; 32] = [0x011; 32];

    #[derive(thiserror::Error, Debug)]
    enum AppErrorExt {
        #[error("AppError: {0}")]
        AppError(#[from] AppError),
        #[error("Future timeout")]
        Elapsed,
        #[error("Proof generation failed: {0}")]
        ProofGeneration(#[from] ProofGenerationStringError),
        #[error("Proof verification failed")]
        ProofVerification,
        #[error("Exiting...")]
        Exit,
    }

    async fn proof_sender(
        sender: Address,
        proof_tx: &mut async_channel::Sender<ProofGenerationData>,
        rln_identifier: Arc<RlnIdentifier>,
        user_db: &UserDb,
    ) -> Result<(), AppErrorExt> {
        // used by test_proof_generation unit test

        debug!("Starting proof sender...");
        debug!("Waiting a bit before sending proof...");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        debug!("Sending proof...");
        proof_tx
            .send(ProofGenerationData {
                user_identity: user_db.get_user(&ADDR_1).unwrap(),
                rln_identifier,
                tx_counter: 0,
                tx_sender: sender,
                tx_hash: TX_HASH_1.to_vec(),
            })
            .await
            .unwrap();
        debug!("Sending proof done");
        // tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        Ok::<(), AppErrorExt>(())
    }

    async fn proof_verifier(
        broadcast_receiver: &mut broadcast::Receiver<
            Result<ProofSendingData, ProofGenerationStringError>,
        >,
        verifying_key: &VerifyingKey<Curve>,
    ) -> Result<(), AppErrorExt> {
        // used by test_proof_generation unit test

        debug!("Starting broadcast receiver...");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let res =
            tokio::time::timeout(std::time::Duration::from_secs(5), broadcast_receiver.recv())
                .await
                .map_err(|_e| AppErrorExt::Elapsed)?;
        debug!("res: {:?}", res);

        let res = res.unwrap();
        let res = res?;
        let mut proof_cursor = Cursor::new(&res.proof);
        debug!("proof cursor: {:?}", proof_cursor);
        let proof = ArkProof::deserialize_compressed(&mut proof_cursor).unwrap();
        let position = proof_cursor.position() as usize;
        let proof_cursor_2 = &proof_cursor.get_ref().as_slice()[position..];
        let (proof_values, _) = deserialize_proof_values(proof_cursor_2);
        debug!("[proof verifier] proof: {:?}", proof);
        debug!("[proof verifier] proof_values: {:?}", proof_values);

        let verified = verify_proof(verifying_key, &proof, &proof_values)
            .map_err(|_e| AppErrorExt::ProofVerification)?;

        debug!("verified: {:?}", verified);

        // Exit after receiving one proof
        Err::<(), AppErrorExt>(AppErrorExt::Exit)
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_proof_generation() {
        // Queues
        let (broadcast_sender, _broadcast_receiver) = broadcast::channel(2);
        let mut broadcast_receiver = broadcast_sender.subscribe();
        let (mut proof_tx, proof_rx) = async_channel::unbounded();

        // Epoch
        let epoch = Epoch::from(11);
        let epoch_slice = EpochSlice::from(42);
        let epoch_store = Arc::new(RwLock::new((epoch, epoch_slice)));

        // User db
        let temp_folder = tempfile::tempdir().unwrap();
        let temp_folder_tree = tempfile::tempdir().unwrap();
        let user_db_service = UserDbService::new(
            PathBuf::from(temp_folder.path()),
            PathBuf::from(temp_folder_tree.path()),
            Default::default(),
            epoch_store.clone(),
            10.into(),
            Default::default(),
        )
        .unwrap();
        let user_db = user_db_service.get_user_db();
        user_db.on_new_user(&ADDR_1).unwrap();
        user_db.on_new_user(&ADDR_2).unwrap();

        let rln_identifier = Arc::new(RlnIdentifier::new(b"foo bar baz"));

        // Proof service
        let proof_service = ProofService::new(
            proof_rx,
            broadcast_sender,
            epoch_store,
            user_db.clone(),
            RateLimit::from(10),
            0,
        );

        // Verification
        let proving_key = zkey_from_folder();
        let verification_key = &proving_key.0.vk;

        info!("Starting...");
        let res = tokio::try_join!(
            proof_service.serve().map_err(AppErrorExt::AppError),
            proof_verifier(&mut broadcast_receiver, verification_key),
            proof_sender(ADDR_1, &mut proof_tx, rln_identifier.clone(), &user_db),
        );

        // Everything ok if proof_verifier return AppErrorExt::Exit else there is a real error
        assert_matches!(res, Err(AppErrorExt::Exit));
    }
}
