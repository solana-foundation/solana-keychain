//! SDK adapter layer for supporting multiple Solana SDK versions
//!
//! This module provides a unified interface over Solana SDK v2 and v3,
//! abstracting away breaking changes between versions.

#[cfg(feature = "sdk-v2")]
mod v2;
#[cfg(feature = "sdk-v3")]
mod v3;

// Re-export the appropriate version based on feature flags
#[cfg(feature = "sdk-v2")]
pub use v2::*;

#[cfg(feature = "sdk-v3")]
pub use v3::*;

// Compile-time check to ensure exactly one SDK version is enabled
#[cfg(all(feature = "sdk-v2", feature = "sdk-v3"))]
compile_error!("Cannot enable both sdk-v2 and sdk-v3 features. Choose one.");

#[cfg(not(any(feature = "sdk-v2", feature = "sdk-v3")))]
compile_error!("Must enable either sdk-v2 or sdk-v3 feature.");
