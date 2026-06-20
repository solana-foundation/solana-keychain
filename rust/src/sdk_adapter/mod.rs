//! SDK adapter layer for supporting multiple Solana SDK versions
//!
//! This module provides a unified interface over Solana SDK v2, v3, and v4,
//! abstracting away breaking changes between versions.

#[cfg(feature = "sdk-v2")]
mod v2;
#[cfg(feature = "sdk-v3")]
mod v3;
#[cfg(feature = "sdk-v4")]
mod v4;

// Re-export the appropriate version based on feature flags
#[cfg(feature = "sdk-v2")]
pub use v2::*;

#[cfg(feature = "sdk-v3")]
pub use v3::*;

#[cfg(feature = "sdk-v4")]
pub use v4::*;

// Compile-time checks to ensure exactly one SDK version is enabled
#[cfg(any(
    all(feature = "sdk-v2", feature = "sdk-v3"),
    all(feature = "sdk-v2", feature = "sdk-v4"),
    all(feature = "sdk-v3", feature = "sdk-v4"),
))]
compile_error!("Cannot enable more than one of sdk-v2, sdk-v3, sdk-v4. Choose one.");

#[cfg(not(any(feature = "sdk-v2", feature = "sdk-v3", feature = "sdk-v4")))]
compile_error!("Must enable one of sdk-v2, sdk-v3, or sdk-v4 feature.");
