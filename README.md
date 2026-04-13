# agent-vault — Zero-Knowledge eBPF Credential Injector (v2)

An AI coding agent sends HTTP requests using a **dummy token** (`FAKE_TOKEN_12345`).  
An eBPF `cgroup_skb/egress` hook intercepts every outbound TCP packet from that agent's cgroup, locates the dummy token in the payload, and overwrites it with the **real credential** before the packet leaves the host.  
The agent process — and any logs it emits — only ever sees the fake token.

```
AI Agent  →  [FAKE_TOKEN_12345]  →  eBPF hook  →  [REAL_SECRET_9999]  →  Server
```

---

## Prerequisites

| Requirement | Minimum | Verify |
|---|---|---|
| Linux kernel | **5.8+** | `uname -r` |
| cgroup v2 (unified hierarchy) | required | `stat -f --format="%T" /sys/fs/cgroup` → must print `cgroup2fs` |
| Docker | 20.10+ | `docker version` |
| Rust stable | 1.78+ | `rustup show` |
| Rust nightly | any | `rustup toolchain install nightly` |

> **macOS / cgroup v1 hosts:** This project requires a real Linux kernel with cgroup v2.  
> On macOS use Docker Desktop with a Linux VM, or a remote Linux machine.  
> If `stat -f /sys/fs/cgroup` prints `tmpfs` the host uses cgroup v1 — reboot with  
> `systemd.unified_cgroup_hierarchy=1` on the kernel command line.

---

## Project layout

```
orouboros/
├── Cargo.toml                  # Cargo workspace
├── Dockerfile                  # Two-stage build: eBPF → user-space daemon
├── docker-compose.yml
├── agent-vault-common/         # no_std shared structs (kernel ↔ user boundary)
├── agent-vault-ebpf/           # Kernel-space eBPF interceptor (nightly, BPF target)
└── agent-vault/                # User-space Tokio daemon (stable)
```

---

## Build & run (Docker — recommended)

```bash
# 1. Verify cgroup v2 on the host
stat -f --format="%T" /sys/fs/cgroup
# Expected: cgroup2fs

# 2. Build the container image (compiles both eBPF and daemon inside the image)
docker compose build

# 3. Start the daemon
docker compose up
```

The daemon will print:
```
agent-vault is running.

To test, in another terminal:
  echo $$ | sudo tee /sys/fs/cgroup/agent-vault-test/cgroup.procs
  curl -v -H "Authorization: Bearer FAKE_TOKEN_12345" http://httpbin.org/headers
```

---

## Manual build (Linux host without Docker)

```bash
# Step 1: compile the eBPF kernel-side program
cargo +nightly build \
  --package agent-vault-ebpf \
  --target bpfel-unknown-none \
  -Z build-std=core \
  --release

# Step 2: compile the user-space daemon (embeds the eBPF object via include_bytes!)
cargo build --package agent-vault --release

# Step 3: run (requires CAP_BPF + CAP_NET_ADMIN)
sudo ./target/release/agent-vault
```

---

## Testing the intercept

In a **second terminal**, after the daemon is running:

```bash
# Move your shell into the test cgroup
echo $$ | sudo tee /sys/fs/cgroup/agent-vault-test/cgroup.procs

# Make a request with the dummy token
curl -v -H "Authorization: Bearer FAKE_TOKEN_12345" http://httpbin.org/headers
```

**Expected response** (httpbin echoes back what it received):
```json
{
  "headers": {
    "Authorization": "Bearer REAL_SECRET_9999",
    ...
  }
}
```

The agent sent `FAKE_TOKEN_12345`; the server saw `REAL_SECRET_9999`.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Docker Container (privileged, pid: host)               │
│                                                         │
│  ┌──────────────────────┐   eBPF HashMap (cgroup_id →  │
│  │  agent-vault daemon  │──── TokenPair)                │
│  │  (Tokio, user-space) │                   │           │
│  │  • loads eBPF prog   │                   ▼           │
│  │  • creates cgroup    │  ┌────────────────────────┐   │
│  │  • populates map     │  │ Kernel: cgroup_skb/    │   │
│  └──────────────────────┘  │ egress hook            │   │
│                             │ 1. get cgroup ID       │   │
│                             │ 2. map lookup          │   │
│                             │ 3. find dummy token    │   │
│                             │ 4. overwrite w/ real   │   │
│                             │ 5. fix L3/L4 checksums │   │
│                             └────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## Debugging

### eBPF log output

Kernel log lines are forwarded to the host logger via `aya-log`. Set `RUST_LOG=info` to see them:

```
[agent-vault-ebpf] INFO: Map hit for cgroup_id=12345
[agent-vault-ebpf] INFO: Dummy token at offset 234; rewriting
[agent-vault-ebpf] INFO: Payload rewritten & checksums updated
```

### Common failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `Permission denied` on BPF load | Missing `CAP_BPF`/`CAP_NET_ADMIN` | Ensure container uses `privileged: true` |
| cgroup ID is always 0 | PID namespace isolation | Use `pid: host` in docker-compose |
| Token not replaced | `curl` not in the test cgroup | Run `echo $$ \| sudo tee …/cgroup.procs` first |
| TCP checksum rejected by server | Missing `BPF_F_PSEUDO_HDR` | Already fixed in v2 — verify you built latest code |
| eBPF program rejected by verifier | Unbounded loop / missing bounds check | Check `ctx.len()` guard in `try_intercept` |
| `cgroup2fs` not found | Host uses cgroup v1 | Reboot with `systemd.unified_cgroup_hierarchy=1` |

---

## Out of scope (Phase 1)

- **HTTPS / TLS** — eBPF cannot inspect encrypted payloads without uprobes on the TLS library.
- **Token rotation** — the map is populated once at startup.
- **Multi-agent isolation** — one `TokenPair` per `cgroup_id`; separate cgroups needed for multiple agents.
- **Production hardening** — privilege scoping, seccomp profiles, read-only rootfs, BPF map pinning.
