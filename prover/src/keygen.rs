//! Proving and Verifying Key Generation
//!
//! Handles generation, caching, and loading of Halo2 proving and verifying keys.

use anyhow::{Context, Result};
use bpf_tracer::ExecutionTrace;
use halo2_base::{
    gates::{
        circuit::{
            builder::BaseCircuitBuilder,
            BaseCircuitParams,
            CircuitBuilderStage,
        },
        flex_gate::GateChip,
    },
    halo2_proofs::{
        plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
        poly::kzg::commitment::ParamsKZG,
        poly::commitment::Params,
        SerdeFormat,
    },
    halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine},
};
use rand::rngs::OsRng;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use zk_circuits::CounterCircuit;

/// Configuration for key generation
#[derive(Debug, Clone)]
pub struct KeygenConfig {
    /// Circuit size parameter (circuit has 2^k rows)
    pub k: u32,
    /// Directory to cache keys
    pub cache_dir: PathBuf,
    /// Lookup bits for range checks
    pub lookup_bits: usize,
}

impl KeygenConfig {
    /// Create a new keygen configuration
    pub fn new(k: u32, cache_dir: impl Into<PathBuf>, lookup_bits: usize) -> Self {
        Self {
            k,
            cache_dir: cache_dir.into(),
            lookup_bits,
        }
    }

    /// Get path to cached parameters file
    fn params_path(&self) -> PathBuf {
        self.cache_dir.join(format!("params_k{}.bin", self.k))
    }

    /// Get path to cached verifying key file
    fn vk_path(&self) -> PathBuf {
        self.cache_dir.join(format!("counter_vk_k{}.bin", self.k))
    }

    /// Get path to cached proving key file
    fn pk_path(&self) -> PathBuf {
        self.cache_dir.join(format!("counter_pk_k{}.bin", self.k))
    }
}

impl Default for KeygenConfig {
    fn default() -> Self {
        Self {
            k: 17, // 2^17 = 131,072 rows
            cache_dir: PathBuf::from(".cache/keys"),
            lookup_bits: 8,
        }
    }
}

/// Key pair for proving and verification
#[derive(Debug)]
pub struct KeyPair {
    /// KZG parameters
    pub params: ParamsKZG<Bn256>,
    /// Proving key
    pub pk: ProvingKey<G1Affine>,
    /// Verifying key (extracted from proving key)
    pub vk: VerifyingKey<G1Affine>,
}

impl KeyPair {
    /// Load or generate keys based on configuration
    ///
    /// If cached keys exist and are valid, loads them from disk.
    /// Otherwise, generates new keys and caches them.
    pub fn load_or_generate(config: &KeygenConfig) -> Result<Self> {
        // Check if cached keys exist
        if Self::cache_exists(config) {
            tracing::info!("Found cached keys, attempting to load...");
            match Self::load_from_cache(config) {
                Ok(keypair) => {
                    tracing::info!("Successfully loaded keys from cache");
                    return Ok(keypair);
                }
                Err(e) => {
                    tracing::warn!("Failed to load cached keys: {}. Regenerating...", e);
                }
            }
        }

        // Generate new keys
        tracing::info!("Generating new keys...");
        let keypair = Self::generate(config)?;

        // Cache the generated keys
        keypair.save_to_cache(config)
            .context("Failed to cache generated keys")?;

        Ok(keypair)
    }

    /// Generate new keys (bypasses cache)
    pub fn generate(config: &KeygenConfig) -> Result<Self> {
        tracing::info!(
            "Generating proving and verifying keys for k={}, lookup_bits={}",
            config.k,
            config.lookup_bits
        );

        // Set up KZG parameters
        tracing::info!("Setting up KZG parameters...");
        let params = ParamsKZG::<Bn256>::setup(config.k, OsRng);

        // Set environment variable for lookup bits
        std::env::set_var("LOOKUP_BITS", config.lookup_bits.to_string());

        // Create a dummy circuit for keygen
        tracing::info!("Creating dummy circuit for keygen...");
        let dummy_trace = ExecutionTrace::new();
        let circuit_logic = CounterCircuit::from_trace(dummy_trace);

        // Build the circuit using BaseCircuitBuilder
        let mut builder = BaseCircuitBuilder::<Fr>::from_stage(CircuitBuilderStage::Keygen)
            .use_k(config.k as usize)
            .use_lookup_bits(config.lookup_bits);

        // Create a gate chip
        let gate = GateChip::<Fr>::default();

        // Synthesize the circuit
        circuit_logic.synthesize(builder.main(0), &gate)
            .context("Failed to synthesize circuit")?;

        // Configure the builder
        builder.calculate_params(Some(9));

        // Generate verifying key
        tracing::info!("Generating verifying key...");
        let vk = keygen_vk(&params, &builder)
            .context("Failed to generate verifying key")?;

        // Generate proving key
        tracing::info!("Generating proving key...");
        let pk = keygen_pk(&params, vk, &builder)
            .context("Failed to generate proving key")?;

        let vk = pk.get_vk().clone();

        tracing::info!("Key generation complete");
        Ok(Self { params, pk, vk })
    }

    /// Load keys from cache
    pub fn load_from_cache(config: &KeygenConfig) -> Result<Self> {
        tracing::info!("Loading keys from cache: {:?}", config.cache_dir);

        let params = load_params(&config.params_path())
            .context("Failed to load KZG parameters")?;

        let vk = load_vk(&params, &config.vk_path())
            .context("Failed to load verifying key")?;

        let pk = load_pk(&params, &config.pk_path())
            .context("Failed to load proving key")?;

        tracing::info!("Successfully loaded keys from cache");
        Ok(Self { params, vk, pk })
    }

    /// Save keys to cache
    pub fn save_to_cache(&self, config: &KeygenConfig) -> Result<()> {
        // Create cache directory if it doesn't exist
        fs::create_dir_all(&config.cache_dir)
            .context("Failed to create cache directory")?;

        tracing::info!("Saving keys to cache: {:?}", config.cache_dir);

        save_params(&self.params, &config.params_path())
            .context("Failed to save KZG parameters")?;

        save_vk(&self.vk, &config.vk_path())
            .context("Failed to save verifying key")?;

        save_pk(&self.pk, &config.pk_path())
            .context("Failed to save proving key")?;

        tracing::info!("Successfully saved keys to cache");
        Ok(())
    }

    /// Check if cached keys exist for given configuration
    pub fn cache_exists(config: &KeygenConfig) -> bool {
        config.params_path().exists()
            && config.vk_path().exists()
            && config.pk_path().exists()
    }
}

/// Load KZG parameters from file
fn load_params(path: &Path) -> Result<ParamsKZG<Bn256>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open params file: {:?}", path))?;
    let mut reader = BufReader::new(file);

    ParamsKZG::<Bn256>::read(&mut reader)
        .with_context(|| format!("Failed to deserialize params from {:?}", path))
}

/// Save KZG parameters to file
fn save_params(params: &ParamsKZG<Bn256>, path: &Path) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Failed to create params file: {:?}", path))?;
    let mut writer = BufWriter::new(file);

    params.write(&mut writer)
        .with_context(|| format!("Failed to serialize params to {:?}", path))?;

    Ok(())
}

/// Load verifying key from file
fn load_vk(
    _params: &ParamsKZG<Bn256>,
    path: &Path,
) -> Result<VerifyingKey<G1Affine>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open VK file: {:?}", path))?;
    let mut reader = BufReader::new(file);

    // Use default circuit params for loading (values don't matter for deserialization)
    let params = BaseCircuitParams::default();

    VerifyingKey::<G1Affine>::read::<_, BaseCircuitBuilder<Fr>>(
        &mut reader,
        SerdeFormat::RawBytesUnchecked,
        params,
    )
    .with_context(|| format!("Failed to deserialize VK from {:?}", path))
}

/// Save verifying key to file
fn save_vk(vk: &VerifyingKey<G1Affine>, path: &Path) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Failed to create VK file: {:?}", path))?;
    let mut writer = BufWriter::new(file);

    vk.write(&mut writer, SerdeFormat::RawBytesUnchecked)
        .with_context(|| format!("Failed to serialize VK to {:?}", path))?;

    Ok(())
}

/// Load proving key from file
fn load_pk(
    _params: &ParamsKZG<Bn256>,
    path: &Path,
) -> Result<ProvingKey<G1Affine>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open PK file: {:?}", path))?;
    let mut reader = BufReader::new(file);

    // Use default circuit params for loading (values don't matter for deserialization)
    let params = BaseCircuitParams::default();

    ProvingKey::<G1Affine>::read::<_, BaseCircuitBuilder<Fr>>(
        &mut reader,
        SerdeFormat::RawBytesUnchecked,
        params,
    )
    .with_context(|| format!("Failed to deserialize PK from {:?}", path))
}

/// Save proving key to file
fn save_pk(pk: &ProvingKey<G1Affine>, path: &Path) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Failed to create PK file: {:?}", path))?;
    let mut writer = BufWriter::new(file);

    pk.write(&mut writer, SerdeFormat::RawBytesUnchecked)
        .with_context(|| format!("Failed to serialize PK to {:?}", path))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_keygen_config_default() {
        let config = KeygenConfig::default();
        assert_eq!(config.k, 17);
        assert_eq!(config.lookup_bits, 8);
    }

    #[test]
    fn test_keygen_config_paths() {
        let config = KeygenConfig::new(10, "/tmp/test_keys", 8);

        assert_eq!(config.params_path(), PathBuf::from("/tmp/test_keys/params_k10.bin"));
        assert_eq!(config.vk_path(), PathBuf::from("/tmp/test_keys/counter_vk_k10.bin"));
        assert_eq!(config.pk_path(), PathBuf::from("/tmp/test_keys/counter_pk_k10.bin"));
    }

    #[test]
    fn test_cache_exists_returns_false_for_nonexistent() {
        let temp_dir = env::temp_dir().join("nonexistent_keygen_test");
        let config = KeygenConfig::new(10, temp_dir, 8);

        assert!(!KeyPair::cache_exists(&config));
    }

    #[test]
    fn test_load_or_generate_not_implemented() {
        let config = KeygenConfig::default();
        let result = KeyPair::load_or_generate(&config);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not yet implemented"));
    }
}
