# Agent-Vault: Zero-Knowledge eBPF Credential Injector (v2 — Containerized)

## 1. System Context & Objective

We are building a "Zero-Knowledge Vault" for local AI coding agents. The goal is to allow an AI agent to make authenticated network requests using a **Dummy Token** (e.g., `FAKE_TOKEN_12345`). The agent never has access to the real credentials.

An eBPF program intercepts outbound network packets, identifies the dummy token in the TCP payload, rewrites it with the real credential, recalculates TCP/IP checksums, and forwards the packet. The target server receives a valid request; the AI agent is completely blind to the real credential.

**v2 changes from v1:**
- Containerized execution environment (Docker) replacing bare-metal assumptions
- Fixed `cgroup_id` retrieval API (`bpf_get_current_cgroup_id()`, not `ctx.cb()`)
- Explicit cgroup v2 (`cgroupfs`) bind-mount and unified hierarchy requirements
- Correct `BPF_F_PSEUDO_HDR` flag usage for TCP checksum helpers
- Explicit `CAP_BPF` + `CAP_NET_ADMIN` capability requirements documented
- Struct alignment and verifier-compliance notes
- Kernel version gate (≥ 5.8 required for `cgroup_skb` + `bpf_get_current_cgroup_id`)

---

## 2. Prerequisites & Environment

### 2.1 Host Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| Linux kernel | **5.8+** | Required for `bpf_get_current_cgroup_id()` in `cgroup_skb` context |
| cgroup version | **cgroup v2 only** | Unified hierarchy at `/sys/fs/cgroup` |
| Docker | 20.10+ | For `--privileged` and cgroup bind-mount support |
| Rust toolchain | stable + `nightly` | `nightly` for eBPF cross-compilation |

Verify cgroup v2 is active on the host:
```bash
stat -f --format="%T" /sys/fs/cgroup
# Must output: cgroup2fs
# If output is tmpfs, the host uses cgroup v1 — reboot with kernel param: systemd.unified_cgroup_hierarchy=1
```

### 2.2 Container Setup

The daemon **must** run in a privileged container with the host's cgroup filesystem bind-mounted. This is the only supported execution environment in v2.

**`Dockerfile`:**
```dockerfile
FROM rust:1.78-slim-bookworm

# System deps
RUN apt-get update && apt-get install -y \
    llvm clang libelf-dev linux-headers-generic \
    bpftool iproute2 curl && rm -rf /var/lib/apt/lists/*

# Rust targets for eBPF cross-compilation
RUN rustup toolchain install nightly && \
    rustup component add rust-src --toolchain nightly

# cargo-bpf / aya-tool
RUN cargo install bpf-linker

WORKDIR /app
COPY . .

RUN cargo build --release
```

**`docker-compose.yml`:**
```yaml
version: "3.9"
services:
  agent-vault:
    build: .
    privileged: true                    # Required: CAP_BPF + CAP_NET_ADMIN
    pid: host                           # Required: access host cgroup IDs
    volumes:
      - /sys/fs/cgroup:/sys/fs/cgroup   # Bind-mount host cgroupfs (read-write)
    command: ["./target/release/agent-vault"]
```

> **Security Note:** `privileged: true` grants full CAP_* access. In production, scope down to `cap_add: [CAP_BPF, CAP_NET_ADMIN, CAP_SYS_ADMIN]` and use a read-only root filesystem. For MVP, `privileged` is acceptable.

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────┐
│  Docker Container (privileged)                      │
│                                                     │
│  ┌─────────────────────┐   eBPF Map (HashMap)       │
│  │  agent-vault        │──────────────────────┐     │
│  │  (user-space, Tokio)│                      │     │
│  │  - loads eBPF prog  │                      ▼     │
│  │  - creates cgroup   │   { cgroup_id →  TokenPair}│
│  │  - populates map    │                      │     │
│  └─────────────────────┘                      │     │
│                                               │     │
│  ┌─────────────────────────────────────────┐  │     │
│  │  Kernel Space                           │  │     │
│  │  cgroup_skb/egress hook                 │◄─┘     │
│  │  ┌───────────────────────────────────┐  │        │
│  │  │ 1. bpf_get_current_cgroup_id()    │  │        │
│  │  │ 2. map lookup                     │  │        │
│  │  │ 3. parse IP + TCP headers         │  │        │
│  │  │ 4. scan payload for dummy_token   │  │        │
│  │  │ 5. bpf_skb_store_bytes()          │  │        │
│  │  │ 6. bpf_l3_csum_replace()          │  │        │
│  │  │ 7. bpf_l4_csum_replace()          │  │        │
│  │  └───────────────────────────────────┘  │        │
│  └─────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────┘
```

**Crate layout (Rust workspace):**

```
agent-vault/
├── Cargo.toml                  # workspace
├── agent-vault-common/         # shared structs (no_std)
├── agent-vault-ebpf/           # kernel-space eBPF program
└── agent-vault/                # user-space daemon (Tokio)
```

---

## 4. Implementation Instructions

### Phase 1: Shared Structures (`agent-vault-common`)

This crate must compile for both `std` (user-space) and `no_std` (eBPF kernel-space).

**Key design constraints:**
- All fields must be `#[repr(C)]` for ABI stability across the kernel/user boundary
- Arrays must be power-of-2 sized to satisfy eBPF verifier alignment rules
- No heap allocation — fixed-size arrays only
- Token arrays are **16 bytes** — tokens must be zero-padded to fill the array exactly

```rust
// agent-vault-common/src/lib.rs
#![no_std]

/// Stored in the eBPF HashMap, keyed by cgroup_id (u64).
/// MUST be #[repr(C)] — the eBPF verifier enforces C ABI layout.
/// Fixed 16-byte arrays satisfy verifier alignment requirements.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TokenPair {
    /// The placeholder token the AI agent sends (e.g. b"FAKE_TOKEN_12345")
    pub dummy_token: [u8; 16],
    /// The real credential to substitute in (e.g. b"REAL_SECRET_9999")
    pub real_token:  [u8; 16],
}
```

**`Cargo.toml` for common:**
```toml
[package]
name = "agent-vault-common"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-ebpf = { version = "0.1", optional = true }   # only for ebpf crate

[features]
default = []
ebpf = ["aya-ebpf"]
```

---

### Phase 2: User-Space Daemon (`agent-vault`)

**Responsibilities:**
1. Load the compiled eBPF object (`.o` file produced by the eBPF crate)
2. Create the test cgroup under the host-mounted cgroupfs
3. Attach the `cgroup_skb/egress` program to the cgroup
4. Read the cgroup's numeric ID from `fd`
5. Populate the eBPF HashMap with the `TokenPair`
6. Block on Ctrl+C (daemon mode)

**Critical implementation notes:**

```rust
// agent-vault/src/main.rs

use aya::{Bpf, programs::{CgroupSkb, CgroupSkbAttachType}};
use aya::maps::HashMap;
use agent_vault_common::TokenPair;
use std::fs;
use tokio::signal;

const CGROUP_PATH: &str = "/sys/fs/cgroup/agent-vault-test";
const DUMMY: &[u8; 16] = b"FAKE_TOKEN_12345";
const REAL:  &[u8; 16] = b"REAL_SECRET_9999";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Load eBPF bytecode
    let mut bpf = Bpf::load(include_bytes!(
        "../../target/bpfel-unknown-none/release/agent-vault-ebpf"
    ))?;

    // 2. Create cgroup (cgroup v2 unified hierarchy)
    //    Path is under the bind-mounted /sys/fs/cgroup from the host.
    fs::create_dir_all(CGROUP_PATH)?;

    // 3. Open cgroup fd and attach program
    let cgroup_file = fs::File::open(CGROUP_PATH)?;
    let program: &mut CgroupSkb = bpf
        .program_mut("cgroup_skb_egress")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(&cgroup_file, CgroupSkbAttachType::Egress)?;

    // 4. Retrieve the cgroup ID
    //    The cgroup ID is the inode number of the cgroup directory on cgroupfs.
    //    aya provides this via the fd.
    use std::os::unix::fs::MetadataExt;
    let cgroup_id: u64 = fs::metadata(CGROUP_PATH)?.ino();
    println!("[agent-vault] cgroup_id = {}", cgroup_id);

    // 5. Populate the eBPF map
    let mut token_map: HashMap<_, u64, TokenPair> =
        HashMap::try_from(bpf.map_mut("TOKEN_MAP").unwrap())?;

    let pair = TokenPair {
        dummy_token: *DUMMY,
        real_token:  *REAL,
    };
    token_map.insert(cgroup_id, pair, 0)?;
    println!("[agent-vault] TokenPair inserted for cgroup {}", cgroup_id);

    // 6. Wait for shutdown
    println!("[agent-vault] Running. Press Ctrl+C to exit.");
    signal::ctrl_c().await?;

    // 7. Cleanup: remove the test cgroup
    fs::remove_dir(CGROUP_PATH)?;
    println!("[agent-vault] Cgroup removed. Exiting.");
    Ok(())
}
```

**`Cargo.toml` for user-space:**
```toml
[package]
name = "agent-vault"
version = "0.1.0"
edition = "2021"

[dependencies]
aya            = "0.12"
aya-log        = "0.2"
agent-vault-common = { path = "../agent-vault-common" }
anyhow         = "1"
tokio          = { version = "1", features = ["macros", "rt", "signal"] }
log            = "0.4"
env_logger     = "0.10"
```

---

### Phase 3: eBPF Interceptor (`agent-vault-ebpf`)

**Critical fixes from v1:**

| v1 Bug | v2 Fix |
|---|---|
| `ctx.cb()` to get cgroup ID | `bpf_get_current_cgroup_id()` — the correct BPF helper |
| Missing `BPF_F_PSEUDO_HDR` flag on `bpf_l4_csum_replace` | Must pass `BPF_F_PSEUDO_HDR` so the kernel includes the IP pseudo-header in TCP checksum calculation |
| No explicit verifier safety around array bounds | Add explicit length checks before any `bpf_skb_load_bytes` call |

```rust
// agent-vault-ebpf/src/main.rs
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_PSEUDO_HDR,
    helpers::{
        bpf_get_current_cgroup_id,
        bpf_l3_csum_replace,
        bpf_l4_csum_replace,
        bpf_skb_load_bytes,
        bpf_skb_store_bytes,
    },
    macros::{cgroup_skb, map},
    maps::HashMap,
    programs::SkBuffContext,
};
use aya_log_ebpf::info;
use agent_vault_common::TokenPair;

// eBPF HashMap: cgroup_id (u64) → TokenPair
#[map(name = "TOKEN_MAP")]
static TOKEN_MAP: HashMap<u64, TokenPair> = HashMap::with_max_entries(64, 0);

// IPv4 header constants
const ETH_HDR_LEN:  u32 = 14;
const IPV4_HDR_LEN: u32 = 20;  // assuming no IP options (MVP)
const TCP_HDR_LEN:  u32 = 20;  // assuming no TCP options (MVP)
const PAYLOAD_OFFSET: u32 = ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN;

// IPv4 checksum field offset (from start of IP header)
const IP_CSUM_OFFSET:  u32 = ETH_HDR_LEN + 10;
// TCP checksum field offset (from start of TCP header)
const TCP_CSUM_OFFSET: u32 = ETH_HDR_LEN + IPV4_HDR_LEN + 16;

const TOKEN_LEN: usize = 16;

#[cgroup_skb(name = "cgroup_skb_egress")]
pub fn cgroup_skb_egress(ctx: SkBuffContext) -> i32 {
    match try_intercept(&ctx) {
        Ok(ret) => ret,
        Err(_)  => 1,  // on any error, allow the packet through
    }
}

fn try_intercept(ctx: &SkBuffContext) -> Result<i32, i64> {
    // Step 1: Get the cgroup ID of the socket that generated this packet.
    // FIXED from v1: use bpf_get_current_cgroup_id(), NOT ctx.cb().
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    info!(ctx, "Packet Intercepted | Cgroup: {}", cgroup_id);

    // Step 2: Look up the cgroup ID in our map.
    let pair = match unsafe { TOKEN_MAP.get(&cgroup_id) } {
        Some(p) => p,
        None    => return Ok(1),  // not our cgroup, allow packet
    };

    info!(ctx, "Map Match Found for Cgroup {}", cgroup_id);

    // Step 3: Only process IPv4/TCP packets (ETH_P_IP = 0x0800, proto TCP = 6).
    // skb->protocol and skb->cb are accessible via ctx for cgroup_skb programs.
    // For MVP, we trust the packet is HTTP/TCP — add protocol checks for production.

    // Step 4: Load the TCP payload into a stack buffer.
    // eBPF stack is limited to 512 bytes; keep buffer small.
    let mut payload = [0u8; 128];
    let payload_len = payload.len() as u32;

    // Bounds check required before bpf_skb_load_bytes — verifier enforces this.
    if ctx.len() < PAYLOAD_OFFSET + TOKEN_LEN as u32 {
        return Ok(1);  // packet too small to contain our token
    }

    let ret = unsafe {
        bpf_skb_load_bytes(
            ctx.as_ptr() as *const _,
            PAYLOAD_OFFSET,
            payload.as_mut_ptr() as *mut _,
            payload_len,
        )
    };
    if ret < 0 { return Ok(1); }

    // Step 5: Search for dummy_token in the payload buffer.
    let dummy = &pair.dummy_token;
    let mut found_offset: Option<u32> = None;

    // Note: eBPF verifier requires bounded loops; TOKEN_LEN and payload bounds are fixed.
    for i in 0..(payload_len as usize - TOKEN_LEN + 1) {
        if &payload[i..i + TOKEN_LEN] == dummy.as_ref() {
            found_offset = Some(PAYLOAD_OFFSET + i as u32);
            break;
        }
    }

    let offset = match found_offset {
        Some(o) => o,
        None    => return Ok(1),  // token not in this packet
    };

    info!(ctx, "Dummy Token Detected at Offset {}", offset);

    // Step 6: Overwrite dummy_token with real_token in the packet.
    let ret = unsafe {
        bpf_skb_store_bytes(
            ctx.as_ptr() as *const _,
            offset,
            pair.real_token.as_ptr() as *const _,
            TOKEN_LEN as u32,
            0,
        )
    };
    if ret < 0 { return Err(ret); }

    // Step 7a: Recalculate IPv4 header checksum (L3).
    // bpf_l3_csum_replace recomputes the IP header checksum after payload change.
    // For a pure payload swap of equal-length bytes, only L4 checksum changes;
    // the IP header checksum covers only the IP header (not payload), so technically
    // no L3 recalc is needed for a payload-only edit. Include it for correctness.
    unsafe {
        bpf_l3_csum_replace(
            ctx.as_ptr() as *const _,
            IP_CSUM_OFFSET,
            0,  // old value (0 = full recompute)
            0,  // new value (0 = full recompute)
            0,
        );
    }

    // Step 7b: Recalculate TCP checksum (L4).
    // FIXED from v1: BPF_F_PSEUDO_HDR is mandatory for TCP.
    // Without it, the kernel omits the IP pseudo-header from the checksum,
    // producing an incorrect TCP checksum that the remote will reject.
    unsafe {
        bpf_l4_csum_replace(
            ctx.as_ptr() as *const _,
            TCP_CSUM_OFFSET,
            0,  // old value (0 = full recompute)
            0,  // new value (0 = full recompute)
            BPF_F_PSEUDO_HDR as u64,  // CRITICAL: include IP pseudo-header
        );
    }

    info!(ctx, "Payload Rewritten & Checksum Updated");

    Ok(1)  // allow the modified packet
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

**`Cargo.toml` for eBPF:**
```toml
[package]
name = "agent-vault-ebpf"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-ebpf     = "0.1"
aya-log-ebpf = "0.2"
agent-vault-common = { path = "../agent-vault-common", features = ["ebpf"] }

[profile.release]
opt-level = 3
lto = true
```

**Build command for eBPF crate (must cross-compile to BPF target):**
```bash
cargo +nightly build \
  --package agent-vault-ebpf \
  --target bpfel-unknown-none \
  -Z build-std=core \
  --release
```

---

## 5. Containerized Build & Run

```bash
# 1. Build the container image
docker compose build

# 2. Run the daemon (requires privileged access to host cgroupfs)
docker compose up

# 3. In a SEPARATE terminal, move curl into the test cgroup and run the request
CGROUP_PATH="/sys/fs/cgroup/agent-vault-test"
# Write the shell's PID into the cgroup
echo $$ | sudo tee ${CGROUP_PATH}/cgroup.procs

# Run the test — the eBPF program will intercept and rewrite the Authorization header
curl -v -H "Authorization: Bearer FAKE_TOKEN_12345" http://httpbin.org/headers
```

---

## 6. Debugging

### 6.1 eBPF Log Output

In the user-space daemon, initialize `aya_log` to receive kernel log output:

```rust
// In main(), before attaching the program:
aya_log::BpfLogger::init(&mut bpf)?;
```

Expected console output when a matching packet is intercepted:
```
[agent-vault-ebpf] INFO: Packet Intercepted | Cgroup: 12345
[agent-vault-ebpf] INFO: Map Match Found for Cgroup 12345
[agent-vault-ebpf] INFO: Dummy Token Detected at Offset 234
[agent-vault-ebpf] INFO: Payload Rewritten & Checksum Updated
```

### 6.2 Common Failure Modes

| Symptom | Likely Cause | Fix |
|---|---|---|
| `Permission denied` loading eBPF | Missing `CAP_BPF` / `CAP_NET_ADMIN` | Ensure container is `privileged` |
| cgroup ID always 0 | Container PID namespace isolation | Use `pid: host` in compose |
| Token not replaced | curl not in the test cgroup | Run `echo $$ > cgroup.procs` before curl |
| TCP checksum rejected | Missing `BPF_F_PSEUDO_HDR` | Verify flag is set on `bpf_l4_csum_replace` |
| eBPF program rejected by verifier | Unbounded loop or missing bounds check | Add explicit `ctx.len()` guard before `bpf_skb_load_bytes` |
| `cgroup2fs` not found | Host using cgroup v1 | Reboot with `systemd.unified_cgroup_hierarchy=1` |

### 6.3 Verify the Intercept

```bash
# Expected response from httpbin.org showing the REAL token (not the fake one):
{
  "headers": {
    "Authorization": "Bearer REAL_SECRET_9999",
    ...
  }
}
```

If `FAKE_TOKEN_12345` appears instead, the eBPF program is not intercepting (check cgroup membership and logs).

---

## 7. Out of Scope (Phase 1)

- **HTTPS / TLS interception** — eBPF cannot inspect encrypted payloads at the network layer. TLS interception requires uprobes on OpenSSL/BoringSSL and is a separate workstream.
- **Token rotation** — the HashMap is populated once at startup; live updates are out of scope for MVP.
- **Multi-agent isolation** — only one `TokenPair` per `cgroup_id`; multiple agents require separate cgroups.
- **Production hardening** — privilege scoping, seccomp, read-only rootfs, map pinning to BPFFS.
