//! Proving and Verifying Key Generation
//!
//! Handles generation, caching, and loading of Halo2 proving and verifying keys.

use anyhow::{Context, Result};
use halo2_base::halo2_proofs::{
    plonk::{ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
    poly::commitment::Params,
    SerdeFormat,
};
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

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
    pub fn load_or_generate(_config: &KeygenConfig) -> Result<Self> {
        // TODO: Implement actual key generation once CounterCircuit implements Circuit trait
        //
        // The implementation will follow this pattern:
        // 1. Check if cached keys exist using config.params_path(), config.vk_path(), config.pk_path()
        // 2. If they exist, load from disk using load_params, load_vk, load_pk
        // 3. If not, generate using:
        //    - Setup params: ParamsKZG::setup(config.k, OsRng)
        //    - Create dummy circuit: CounterCircuit::from_trace(ExecutionTrace::new())
        //    - Generate VK: keygen_vk(&params, &circuit)
        //    - Generate PK: keygen_pk(&params, vk, &circuit)
        // 4. Cache the generated keys to disk
        //
        // For now, return an error indicating this needs Circuit trait implementation

        anyhow::bail!(
            "Key generation not yet implemented. \
             CounterCircuit must implement halo2_proofs::plonk::Circuit trait first. \
             See halo2-lib/halo2-base/src/gates/tests/bitwise_rotate.rs for reference implementation."
        )
    }

    /// Generate new keys (bypasses cache)
    pub fn generate(_config: &KeygenConfig) -> Result<Self> {
        // TODO: Implement key generation
        // This is called by load_or_generate when cache miss occurs

        anyhow::bail!("Key generation not yet implemented")
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
    _path: &Path,
) -> Result<VerifyingKey<G1Affine>> {
    // TODO: Implement VK loading once CounterCircuit implements Circuit trait
    // The read function requires a ConcreteCircuit type parameter:
    // VerifyingKey::<G1Affine>::read::<BufReader<File>, CounterCircuit>(...)
    anyhow::bail!("VK loading not yet implemented - requires Circuit trait on CounterCircuit")
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
    _path: &Path,
) -> Result<ProvingKey<G1Affine>> {
    // TODO: Implement PK loading once CounterCircuit implements Circuit trait
    // The read function requires a ConcreteCircuit type parameter:
    // ProvingKey::<G1Affine>::read::<BufReader<File>, CounterCircuit>(...)
    anyhow::bail!("PK loading not yet implemented - requires Circuit trait on CounterCircuit")
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
