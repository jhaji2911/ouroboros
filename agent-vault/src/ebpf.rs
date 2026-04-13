//! eBPF mode for agent-vault (Linux only).
//!
//! Loads the compiled eBPF `cgroup_skb/egress` interceptor, creates a test cgroup,
//! attaches the program, and populates the kernel HashMap with the token pair.

use aya::{
    maps::HashMap,
    programs::{CgroupSkb, CgroupSkbAttachType},
    Bpf,
};
use aya_log::BpfLogger;
use agent_vault_common::TokenPair;
use anyhow::{Context, Result};
use std::{fs, os::unix::fs::MetadataExt};
use tokio::signal;

// ---------------------------------------------------------------------------
// Configuration constants
// ---------------------------------------------------------------------------

const CGROUP_PATH: &str = "/sys/fs/cgroup/agent-vault-test";
const DUMMY_TOKEN: &[u8; 16] = b"FAKE_TOKEN_12345";
const REAL_TOKEN: &[u8; 16] = b"REAL_SECRET_9999";

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run_ebpf_mode() -> Result<()> {
    // 1. Load the eBPF object file compiled for bpfel-unknown-none.
    let mut bpf = Bpf::load(include_bytes!(
        "../../target/bpfel-unknown-none/release/agent-vault-ebpf"
    ))
    .context("Failed to load eBPF object. Did you run the eBPF build step first?")?;

    // 2. Route eBPF log output (from aya_log_ebpf::info! calls) to the host logger.
    BpfLogger::init(&mut bpf).context("Failed to init BPF logger")?;

    // 3. Create the test cgroup under the host-mounted cgroupfs (cgroup v2).
    fs::create_dir_all(CGROUP_PATH)
        .with_context(|| format!("Failed to create cgroup at {CGROUP_PATH}. Is cgroup v2 mounted?"))?;
    log::info!("Created cgroup at {}", CGROUP_PATH);

    // 4. Open the cgroup directory as an fd and attach the program.
    let cgroup_file = fs::File::open(CGROUP_PATH)
        .with_context(|| format!("Cannot open cgroup dir {CGROUP_PATH}"))?;

    let program: &mut CgroupSkb = bpf
        .program_mut("cgroup_skb_egress")
        .context("eBPF program 'cgroup_skb_egress' not found in object file")?
        .try_into()
        .context("Program is not of type CgroupSkb")?;

    program.load().context("Failed to load eBPF program into the kernel")?;
    program
        .attach(&cgroup_file, CgroupSkbAttachType::Egress)
        .context("Failed to attach cgroup_skb/egress")?;
    log::info!("eBPF program attached to {}", CGROUP_PATH);

    // 5. Derive the cgroup ID from the inode number of the cgroup directory.
    let cgroup_id: u64 = fs::metadata(CGROUP_PATH)
        .context("Cannot stat cgroup path")?
        .ino();
    log::info!("cgroup_id = {}", cgroup_id);

    // 6. Insert the TokenPair into the shared eBPF HashMap.
    let mut token_map: HashMap<_, u64, TokenPair> =
        HashMap::try_from(bpf.map_mut("TOKEN_MAP").context("TOKEN_MAP not found")?)
            .context("Failed to open TOKEN_MAP as HashMap")?;

    let pair = TokenPair {
        dummy_token: *DUMMY_TOKEN,
        real_token:  *REAL_TOKEN,
    };
    token_map
        .insert(cgroup_id, pair, 0)
        .context("Failed to insert TokenPair into TOKEN_MAP")?;
    log::info!("TokenPair registered for cgroup_id={}", cgroup_id);

    // 7. Print the welcome banner.
    print_banner(cgroup_id);

    // 8. Block until SIGINT / Ctrl-C.
    signal::ctrl_c().await.context("Error waiting for Ctrl-C signal")?;

    // 9. Best-effort cleanup: remove the test cgroup.
    if let Err(e) = fs::remove_dir(CGROUP_PATH) {
        log::warn!("Could not remove cgroup {}: {}", CGROUP_PATH, e);
    } else {
        log::info!("Cgroup {} removed.", CGROUP_PATH);
    }

    println!("Shutting down. The snake rests.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

fn print_banner(cgroup_id: u64) {
    let cyan = "\x1b[36m";
    let green = "\x1b[32m";
    let yellow = "\x1b[33m";
    let bold = "\x1b[1m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    println!();
    println!("{cyan}{bold}");
    println!(r"        ____....----````----....____ ");
    println!(r"   .--``                            ``--. ");
    println!(r" /`   .--.        orouboros           .--.`\ ");
    println!(r"|   /  _  \                          /  _  \ |");
    println!(r"|  | (@) | |    zero-knowledge       | (@) |  |");
    println!(r"|   \  ‾  /     credential vault      \  ‾  / |");
    println!(r" \   `--`    ________________________   `--`  /");
    println!(r"  `>  _     /           ^            \    _ <`");
    println!(r"   | / \   /   [FAKE]───►───[REAL]   \  / \ |");
    println!(r"   |/ ~~\/        eBPF intercepts        \/~~ \|");
    println!(r"   (  o  )     token before it leaves   (  o  )");
    println!(r"    \___/ `>___________________________<` \___/");
    println!(r"           ════════════════════════════       ");
    println!("{reset}");

    println!(
        "{bold}  a g e n t - v a u l t{reset}  {dim}v{}{reset}",
        env!("CARGO_PKG_VERSION")
    );
    println!("{dim}  Zero-Knowledge eBPF Credential Injector — v2{reset}");
    println!();

    println!("{green}  ✔{reset}  eBPF program loaded & attached");
    println!("{green}  ✔{reset}  cgroup created  {dim}{CGROUP_PATH}{reset}");
    println!("{green}  ✔{reset}  cgroup_id       {yellow}{bold}{}{reset}", cgroup_id);
    println!(
        "{green}  ✔{reset}  dummy token     {dim}FAKE_TOKEN_12345{reset}  →  real token injected in-flight"
    );
    println!();

    println!("{bold}  How to test:{reset}");
    println!("  {dim}# 1. Move your shell into the intercepted cgroup:{reset}");
    println!("  echo $$ | sudo tee {}/cgroup.procs", CGROUP_PATH);
    println!();
    println!("  {dim}# 2. Send a request with the dummy token:{reset}");
    println!("  curl -s -H \"Authorization: Bearer FAKE_TOKEN_12345\" http://httpbin.org/headers");
    println!();
    println!("  {dim}# expected: httpbin echoes back 'Bearer REAL_SECRET_9999'{reset}");
    println!();
    println!("  {yellow}Press Ctrl-C to stop.{reset}");
    println!();
}
