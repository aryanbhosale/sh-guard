class ShGuard < Formula
  desc "Semantic shell command safety classifier for AI coding agents"
  homepage "https://github.com/aryanbhosale/sh-guard"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/aryanbhosale/sh-guard/releases/download/v0.1.0/sh-guard-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER"
    end
    on_intel do
      url "https://github.com/aryanbhosale/sh-guard/releases/download/v0.1.0/sh-guard-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/aryanbhosale/sh-guard/releases/download/v0.1.0/sh-guard-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER"
    end
    on_intel do
      url "https://github.com/aryanbhosale/sh-guard/releases/download/v0.1.0/sh-guard-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  def install
    bin.install "sh-guard"
    bin.install "sh-guard-mcp" if File.exist?("sh-guard-mcp")
  end

  test do
    assert_match "SAFE", shell_output("#{bin}/sh-guard 'ls -la'")
  end
end
