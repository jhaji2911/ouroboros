//! Shared types for the agent-vault kernel/user boundary.
//!
//! `no_std` unless the `userspace` feature is enabled, so this crate compiles
//! for both the host (std) daemon and the eBPF (bpfel-unknown-none) target.
#![cfg_attr(not(feature = "userspace"), no_std)]

/// Stored in the eBPF HashMap, keyed by `cgroup_id` (u64).
///
/// **ABI constraints:**
/// - `#[repr(C)]` is mandatory — the eBPF verifier enforces C struct layout.
/// - 16-byte fixed arrays satisfy the verifier's power-of-2 alignment rules.
/// - All tokens must be zero-padded to exactly 16 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TokenPair {
    /// Placeholder token the AI agent sends (e.g. `b"FAKE_TOKEN_12345"`).
    pub dummy_token: [u8; 16],
    /// Real credential substituted into the packet (e.g. `b"REAL_SECRET_9999"`).
    pub real_token: [u8; 16],
}

// Allow user-space aya maps to accept TokenPair as a typed value.
// This impl lives here (not in the daemon crate) because TokenPair is local to this crate,
// which satisfies Rust's orphan rule for implementing a foreign trait.
//
// SAFETY: TokenPair is #[repr(C)], all fields are plain bytes, contains no padding or
// interior mutability, and its size is a power-of-two (32 bytes).
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for TokenPair {}
