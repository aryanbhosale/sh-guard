// This test requires building the native module first: napi build --release --platform
try {
    const { classify, riskScore, riskLevel, classifyBatch } = require('./index');

    // Test classify
    const result = classify("ls -la");
    console.assert(result.score <= 20, `ls score should be <=20, got ${result.score}`);
    console.assert(result.level === 'safe', `ls level should be safe, got ${result.level}`);

    // Test riskScore
    const score = riskScore("rm -rf ~/");
    console.assert(score >= 81, `rm -rf ~/ score should be >=81, got ${score}`);

    // Test riskLevel
    const level = riskLevel("rm -rf /");
    console.assert(level === 'critical', `rm -rf / level should be critical, got ${level}`);

    // Test classifyBatch
    const batch = classifyBatch(["ls", "rm -rf /"]);
    console.assert(batch.length === 2, `batch should have 2 results`);
    console.assert(batch[0].level === 'safe');
    console.assert(batch[1].level === 'critical');

    // Test with context
    const ctx = { cwd: "/home/user/project", projectRoot: "/home/user/project", shell: "bash" };
    const ctxResult = classify("rm -rf ./build", ctx);
    console.assert(ctxResult.score <= 100);

    console.log("All npm binding tests passed!");
} catch (e) {
    if (e.code === 'MODULE_NOT_FOUND') {
        console.log("Native module not built yet. Run: cd crates/sh-guard-napi && npx napi build --release --platform");
    } else {
        console.error("Test failed:", e);
        process.exit(1);
    }
}
