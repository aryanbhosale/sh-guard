class ShGuard < Formula
  desc "Semantic shell command safety classifier for AI coding agents"
  homepage "https://github.com/aryanbhosale/sh-guard"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/aryanbhosale/sh-guard/releases/download/v0.1.0/sh-guard-aarch64-apple-darwin.tar.gz"
      sha256 "fee8a3ada41561a9760600e14b9d155ed37aa8894b6e0ed4d1b77e16bd0db7b1"
    end
    on_intel do
      url "https://github.com/aryanbhosale/sh-guard/releases/download/v0.1.0/sh-guard-x86_64-apple-darwin.tar.gz"
      sha256 "ef58084ce44fdb0b2cf2c6694370de93534d4bec89d63a6bd01133472307976c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/aryanbhosale/sh-guard/releases/download/v0.1.0/sh-guard-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "61e30cafac5e193feba5abe43a928a03e854c8713a5cfcb98f46366bf3d0ec66"
    end
    on_intel do
      url "https://github.com/aryanbhosale/sh-guard/releases/download/v0.1.0/sh-guard-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "2099c03c4d4d692891d46ccd8f67b0ead0dd281b9f300bd26809962add7f6e5f"
    end
  end

  def install
    bin.install "sh-guard"
    bin.install "sh-guard-mcp" if File.exist?("sh-guard-mcp")
  end

  def caveats
    <<~EOS
      To auto-configure all your AI coding agents (Claude Code, Codex, Cursor, etc.):
        sh-guard --setup

      To remove sh-guard from all agents:
        sh-guard --uninstall
    EOS
  end

  test do
    assert_match "SAFE", shell_output("#{bin}/sh-guard 'ls -la'")
  end
end
