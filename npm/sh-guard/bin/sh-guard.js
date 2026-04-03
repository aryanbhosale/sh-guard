#!/usr/bin/env node

const { execFileSync } = require("child_process");
const path = require("path");
const os = require("os");

function getBinaryPath() {
  const platform = os.platform();
  const arch = os.arch();

  let pkgName;
  if (platform === "darwin" && arch === "arm64") pkgName = "sh-guard-cli-darwin-arm64";
  else if (platform === "darwin" && arch === "x64") pkgName = "sh-guard-cli-darwin-x64";
  else if (platform === "linux" && arch === "arm64") pkgName = "sh-guard-cli-linux-arm64";
  else if (platform === "linux" && arch === "x64") pkgName = "sh-guard-cli-linux-x64";
  else if (platform === "win32" && arch === "x64") pkgName = "sh-guard-cli-win32-x64";
  else {
    console.error(`Unsupported platform: ${platform}-${arch}`);
    console.error("Install via: cargo install sh-guard-cli");
    process.exit(1);
  }

  try {
    const binDir = path.dirname(require.resolve(`${pkgName}/package.json`));
    const ext = platform === "win32" ? ".exe" : "";
    return path.join(binDir, "bin", `sh-guard${ext}`);
  } catch {
    console.error(`Platform package ${pkgName} not installed.`);
    console.error("Install via: cargo install sh-guard-cli");
    process.exit(1);
  }
}

const binary = getBinaryPath();
try {
  execFileSync(binary, process.argv.slice(2), { stdio: "inherit" });
} catch (e) {
  process.exit(e.status || 1);
}
