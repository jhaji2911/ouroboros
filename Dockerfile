FROM rust:1.78-slim-bookworm AS builder

# System dependencies for eBPF cross-compilation and aya
RUN apt-get update && apt-get install -y \
    llvm \
    clang \
    libelf-dev \
    linux-headers-generic \
    bpftool \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install nightly toolchain and the cross-compilation source component
RUN rustup toolchain install nightly && \
    rustup component add rust-src --toolchain nightly

# Install bpf-linker (links eBPF LLVM IR → BPF ELF object)
RUN cargo install bpf-linker

WORKDIR /app
COPY . .

# ── Step 1: compile the eBPF kernel-side program ─────────────────────────────
# Must use nightly + bpfel-unknown-none target with a minimal core std.
# The output lands in target/bpfel-unknown-none/release/agent-vault-ebpf
# which is include_bytes!()-embedded by the user-space crate in step 2.
RUN cargo +nightly build \
      --package agent-vault-ebpf \
      --target bpfel-unknown-none \
      -Z build-std=core \
      --release

# ── Step 2: compile the user-space daemon ────────────────────────────────────
# Uses stable toolchain; embeds the eBPF object produced above via include_bytes!.
RUN cargo build --package agent-vault --release

# ─────────────────────────────────────────────────────────────────────────────
# Runtime image — keep it small
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y libelf1 iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/agent-vault .

CMD ["./agent-vault"]
