class ShGuard < Formula
  desc "Semantic shell command safety classifier for AI coding agents"
  homepage "https://github.com/aryanbhosale/sh-guard"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/aryanbhosale/sh-guard/releases/download/v0.1.0/sh-guard-aarch64-apple-darwin.tar.gz"
      sha256 "f6c004268e78501b186c80173ddeae8cbdd2b58681beebafa7598e18863ae1e9"
    end
    on_intel do
      url "https://github.com/aryanbhosale/sh-guard/releases/download/v0.1.0/sh-guard-x86_64-apple-darwin.tar.gz"
      sha256 "74ee5c9221ecef174747d8427134d2237adf21e35d5c09745bdd11049b597fd1"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/aryanbhosale/sh-guard/releases/download/v0.1.0/sh-guard-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "c5a6cf7e95a509a03a8a8b9304c6727699f2697c80b725937e4a504ef33ca733"
    end
    on_intel do
      url "https://github.com/aryanbhosale/sh-guard/releases/download/v0.1.0/sh-guard-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "eee55ee79b8d4d0a9c5adbdc653cd1551ec801123fb1758e8d0f72fa183a02dc"
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
