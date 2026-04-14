class AgentVault < Formula
  desc "Zero-Knowledge Credential Injector — rewrites dummy tokens in HTTP requests before they leave the machine"
  homepage "https://github.com/jhaji2911/ouroboros"
  version "0.1.0"

  # Universal binary (arm64 + x86_64 merged with lipo).
  # SHA256 and URL version are auto-patched by .github/workflows/release-macos.yml
  # when a new tag is pushed. Do not edit these lines manually.
  url "https://github.com/jhaji2911/ouroboros/releases/download/v0.1.0/agent-vault-0.1.0-universal-apple-darwin.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  license "MIT"

  # ── Install ──────────────────────────────────────────────────────────────────
  def install
    bin.install "agent-vault"
  end

  # ── Background service (launchd on macOS) ────────────────────────────────────
  # `brew services start agent-vault`  → loads LaunchAgent, auto-starts at login
  # `brew services stop agent-vault`   → unloads LaunchAgent
  # `brew services restart agent-vault`→ restart without re-installing
  service do
    run          [opt_bin/"agent-vault", "--mode", "proxy"]
    keep_alive   true
    log_path     var/"log/agent-vault.log"
    error_log_path var/"log/agent-vault-error.log"
    # Set the listen port via env so it can be overridden without editing the formula
    environment_variables AGENT_VAULT_PROXY_PORT: "8888"
  end

  # ── Post-install instructions ─────────────────────────────────────────────────
  def caveats
    <<~EOS
      ┌─────────────────────────────────────────────────────────┐
      │           agent-vault  ·  proxy mode                    │
      │   AI agents never see your real credentials             │
      └─────────────────────────────────────────────────────────┘

      The daemon rewrites FAKE_TOKEN_12345 → REAL_SECRET_9999
      in every HTTP request that passes through localhost:8888.

      ─── Step 0: tap the repo (one-time) ────────────────────
        brew tap jhaji2911/ouroboros https://github.com/jhaji2911/ouroboros
        brew install agent-vault

      ─── Step 1: start the background service ────────────────
        brew services start agent-vault

      ─── Step 2: point your shell (and your agents) at it ────
      Add these lines to your ~/.zshrc (or ~/.bashrc):

        export HTTP_PROXY=http://localhost:8888
        export HTTPS_PROXY=http://localhost:8888
        export NO_PROXY=localhost,127.0.0.1

      You can paste this one-liner to do it automatically:

        cat >> ~/.zshrc <<'EOF'
        # agent-vault transparent token rewriter
        export HTTP_PROXY=http://localhost:8888
        export HTTPS_PROXY=http://localhost:8888
        export NO_PROXY=localhost,127.0.0.1
        EOF
        source ~/.zshrc

      ─── Step 3: give your AI agent the dummy token ──────────
      Instead of:
        export OPENAI_API_KEY=sk-your-real-key-here

      Do:
        export OPENAI_API_KEY=FAKE_TOKEN_12345

      The service rewrites it on the way out. The agent, its logs,
      and any code it generates will only ever see FAKE_TOKEN_12345.

      ─── Logs ────────────────────────────────────────────────
        tail -f #{var}/log/agent-vault.log

      ─── Status ──────────────────────────────────────────────
        brew services info agent-vault

    EOS
  end

  test do
    # Smoke-test: binary runs and prints help without error
    assert_match "Zero-Knowledge Credential Injector", shell_output("#{bin}/agent-vault --help")
  end
end
