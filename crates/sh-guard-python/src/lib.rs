use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Parse a Python dict into a ClassifyContext.
fn parse_context(dict: &Bound<'_, PyDict>) -> PyResult<sh_guard_core::ClassifyContext> {
    let cwd: Option<String> = dict
        .get_item("cwd")?
        .and_then(|v| v.extract().ok());
    let project_root: Option<String> = dict
        .get_item("project_root")?
        .and_then(|v| v.extract().ok());
    let home_dir: Option<String> = dict
        .get_item("home_dir")?
        .and_then(|v| v.extract().ok());
    let protected_paths: Vec<String> = dict
        .get_item("protected_paths")?
        .and_then(|v| v.extract().ok())
        .unwrap_or_default();
    let shell = match dict
        .get_item("shell")?
        .and_then(|v| v.extract::<String>().ok())
    {
        Some(s) if s == "zsh" => sh_guard_core::Shell::Zsh,
        _ => sh_guard_core::Shell::Bash,
    };

    Ok(sh_guard_core::ClassifyContext {
        cwd,
        project_root,
        home_dir,
        protected_paths,
        shell,
    })
}

/// Convert an AnalysisResult to a Python dict via JSON round-trip.
fn result_to_pydict<'py>(py: Python<'py>, result: &sh_guard_core::AnalysisResult) -> PyResult<Bound<'py, PyAny>> {
    let json_str = serde_json::to_string(result)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", e)))?;
    let json_mod = py.import("json")?;
    json_mod.call_method1("loads", (json_str,))
}

/// Classify a shell command and return a rich analysis dict.
///
/// Args:
///     command: The shell command string to analyze.
///     context: Optional dict with keys: cwd, project_root, home_dir, protected_paths, shell.
///
/// Returns:
///     A dict containing score, level, risk_factors, pipeline_flow, etc.
#[pyfunction]
#[pyo3(signature = (command, context=None))]
fn classify(py: Python<'_>, command: &str, context: Option<&Bound<'_, PyDict>>) -> PyResult<PyObject> {
    let ctx = context.map(parse_context).transpose()?;
    let result = sh_guard_core::classify(command, ctx.as_ref());
    let dict = result_to_pydict(py, &result)?;
    Ok(dict.into())
}

/// Return just the numeric risk score (0-100) for a command.
#[pyfunction]
fn risk_score(command: &str) -> u8 {
    sh_guard_core::risk_score(command)
}

/// Return the risk level as a string: "safe", "caution", "danger", or "critical".
#[pyfunction]
fn risk_level(command: &str) -> String {
    let level = sh_guard_core::risk_level(command);
    match level {
        sh_guard_core::RiskLevel::Safe => "safe".to_string(),
        sh_guard_core::RiskLevel::Caution => "caution".to_string(),
        sh_guard_core::RiskLevel::Danger => "danger".to_string(),
        sh_guard_core::RiskLevel::Critical => "critical".to_string(),
    }
}

/// Classify multiple commands in batch.
///
/// Args:
///     commands: A list of shell command strings.
///     context: Optional dict with context (same as classify).
///
/// Returns:
///     A list of analysis dicts.
#[pyfunction]
#[pyo3(signature = (commands, context=None))]
fn classify_batch(py: Python<'_>, commands: Vec<String>, context: Option<&Bound<'_, PyDict>>) -> PyResult<PyObject> {
    let ctx = context.map(parse_context).transpose()?;
    let strs: Vec<&str> = commands.iter().map(|s| s.as_str()).collect();
    let results = sh_guard_core::classify_batch(&strs, ctx.as_ref());

    let json_str = serde_json::to_string(&results)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", e)))?;

    let json_mod = py.import("json")?;
    let list = json_mod.call_method1("loads", (json_str,))?;
    Ok(list.into())
}

/// Python module definition for sh_guard.
#[pymodule]
fn sh_guard(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(classify, m)?)?;
    m.add_function(wrap_pyfunction!(risk_score, m)?)?;
    m.add_function(wrap_pyfunction!(risk_level, m)?)?;
    m.add_function(wrap_pyfunction!(classify_batch, m)?)?;
    Ok(())
}
