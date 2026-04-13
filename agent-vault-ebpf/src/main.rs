//! eBPF cgroup_skb/egress interceptor.
//!
//! Loaded by the user-space daemon; attaches to a cgroup and rewrites any TCP
//! payload that contains the registered dummy token, replacing it with the real
//! credential *in-flight*.  The originating process never sees the real token.
//!
//! # Build
//! ```
//! cargo +nightly build \
//!   --package agent-vault-ebpf \
//!   --target bpfel-unknown-none \
//!   -Z build-std=core \
//!   --release
//! ```
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_skb, map},
    maps::HashMap,
    programs::SkBuffContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use agent_vault_common::TokenPair;

// ---------------------------------------------------------------------------
// eBPF map: cgroup_id (u64) → TokenPair
// ---------------------------------------------------------------------------
#[map(name = "TOKEN_MAP")]
static TOKEN_MAP: HashMap<u64, TokenPair> = HashMap::with_max_entries(64, 0);

// ---------------------------------------------------------------------------
// Packet offsets (Ethernet II + IPv4 (no options) + TCP (no options))
// ---------------------------------------------------------------------------
const ETH_HDR_LEN: u32 = 14;
const IPV4_HDR_LEN: u32 = 20; // MVP assumes no IP options
const TCP_HDR_LEN: u32 = 20;  // MVP assumes no TCP options
const PAYLOAD_OFFSET: u32 = ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN; // 54

// Checksum field offsets from start of the raw frame
const IP_CSUM_OFFSET: u32 = ETH_HDR_LEN + 10;              // byte 24
const TCP_CSUM_OFFSET: u32 = ETH_HDR_LEN + IPV4_HDR_LEN + 16; // byte 50

const TOKEN_LEN: usize = 16;
const PAYLOAD_BUF: usize = 128;

// BPF_F_PSEUDO_HDR (0x10): instructs bpf_l4_csum_replace to include the IP
// pseudo-header in the TCP checksum.  Omitting this flag produces invalid TCP
// checksums that the remote peer will silently reject.
const BPF_F_PSEUDO_HDR: u64 = 0x10;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
#[cgroup_skb]
pub fn cgroup_skb_egress(ctx: SkBuffContext) -> i32 {
    match try_intercept(&ctx) {
        Ok(ret) => ret,
        Err(_)  => 1, // on any error, let the original packet through
    }
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------
fn try_intercept(ctx: &SkBuffContext) -> Result<i32, i64> {
    // Step 1 — identify the cgroup that owns this socket.
    // FIXED from v1: bpf_get_current_cgroup_id(), NOT ctx.cb() which is unrelated.
    let cgroup_id = unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() };

    // Step 2 — is this cgroup registered in our map?
    let pair_ptr = match unsafe { TOKEN_MAP.get(&cgroup_id) } {
        Some(ptr) => ptr,
        None      => return Ok(1), // not our cgroup; pass through
    };

    info!(ctx, "Map hit for cgroup_id={}", cgroup_id);

    // Copy the TokenPair off the map pointer onto the BPF stack.
    // This is safe: TokenPair is repr(C) + Copy and the pointer is valid for the
    // lifetime of the BPF program invocation.
    // Copying to the stack also makes subsequent field accesses verifier-friendly.
    let pair: TokenPair = unsafe { *pair_ptr };

    // Step 3 — bounds check: packet must be large enough to contain PAYLOAD_OFFSET + TOKEN_LEN.
    // The verifier requires an explicit guard before any bpf_skb_load_bytes call.
    if ctx.len() < PAYLOAD_OFFSET + TOKEN_LEN as u32 {
        return Ok(1); // packet too small; pass through
    }

    // Step 4 — load up to PAYLOAD_BUF bytes of TCP payload into a stack buffer.
    // Stack is limited to 512 bytes; 128-byte buffer is safe.
    let mut payload = [0u8; PAYLOAD_BUF];

    let ret = unsafe {
        aya_ebpf::helpers::bpf_skb_load_bytes(
            ctx.as_ptr() as *const _,
            PAYLOAD_OFFSET,
            payload.as_mut_ptr() as *mut _,
            PAYLOAD_BUF as u32,
        )
    };
    if ret < 0 {
        return Ok(1); // load failed; pass through
    }

    // Step 5 — scan payload for exactly TOKEN_LEN bytes matching dummy_token.
    // Nested bounded loops; both bounds are compile-time constants, verifier-safe.
    let mut found_offset: Option<u32> = None;

    'outer: for i in 0..(PAYLOAD_BUF - TOKEN_LEN) {
        for j in 0..TOKEN_LEN {
            if payload[i + j] != pair.dummy_token[j] {
                continue 'outer;
            }
        }
        found_offset = Some(PAYLOAD_OFFSET + i as u32);
        break;
    }

    let write_offset = match found_offset {
        Some(o) => o,
        None    => return Ok(1), // dummy token not in this packet; pass through
    };

    info!(ctx, "Dummy token at offset {}; rewriting", write_offset);

    // Step 6 — overwrite dummy_token bytes with real_token in the packet.
    let ret = unsafe {
        aya_ebpf::helpers::bpf_skb_store_bytes(
            ctx.as_ptr() as *mut _,
            write_offset,
            pair.real_token.as_ptr() as *const _,
            TOKEN_LEN as u32,
            0,
        )
    };
    if ret < 0 {
        return Err(ret);
    }

    // Step 7a — recompute IPv4 header checksum (L3).
    // For a payload-only rewrite the IP header itself is unchanged, so L3 recalc
    // is technically a no-op here.  Included for correctness and future-proofing.
    unsafe {
        aya_ebpf::helpers::bpf_l3_csum_replace(
            ctx.as_ptr() as *mut _,
            IP_CSUM_OFFSET,
            0, // old = 0 → full recompute
            0, // new = 0 → full recompute
            0,
        );
    }

    // Step 7b — recompute TCP checksum (L4).
    // FIXED from v1: BPF_F_PSEUDO_HDR is mandatory for TCP.  Without it the kernel
    // omits the IP pseudo-header, producing a checksum the remote will reject.
    unsafe {
        aya_ebpf::helpers::bpf_l4_csum_replace(
            ctx.as_ptr() as *mut _,
            TCP_CSUM_OFFSET,
            0,                // old = 0 → full recompute
            0,                // new = 0 → full recompute
            BPF_F_PSEUDO_HDR, // CRITICAL: include IP pseudo-header
        );
    }

    info!(ctx, "Payload rewritten & checksums updated");

    Ok(1) // allow the *modified* packet
}

// Required for no_std + BPF target — the verifier never actually executes this.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
