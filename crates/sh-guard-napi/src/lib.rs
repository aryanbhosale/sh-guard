#[macro_use]
extern crate napi_derive;

use napi::bindgen_prelude::*;
use sh_guard_core;

#[napi(object)]
pub struct JsClassifyContext {
    pub cwd: Option<String>,
    pub project_root: Option<String>,
    pub home_dir: Option<String>,
    pub protected_paths: Option<Vec<String>>,
    pub shell: Option<String>,
}

impl JsClassifyContext {
    fn into_core_context(self) -> sh_guard_core::ClassifyContext {
        sh_guard_core::ClassifyContext {
            cwd: self.cwd,
            project_root: self.project_root,
            home_dir: self.home_dir,
            protected_paths: self.protected_paths.unwrap_or_default(),
            shell: match self.shell.as_deref() {
                Some("zsh") => sh_guard_core::Shell::Zsh,
                _ => sh_guard_core::Shell::Bash,
            },
        }
    }
}

#[napi]
pub fn classify(command: String, context: Option<JsClassifyContext>) -> Result<serde_json::Value> {
    let ctx = context.map(|c| c.into_core_context());
    let result = sh_guard_core::classify(&command, ctx.as_ref());
    serde_json::to_value(&result)
        .map_err(|e| Error::from_reason(format!("Serialization error: {}", e)))
}

#[napi]
pub fn risk_score(command: String) -> u8 {
    sh_guard_core::risk_score(&command)
}

#[napi]
pub fn risk_level(command: String) -> String {
    format!("{:?}", sh_guard_core::risk_level(&command)).to_lowercase()
}

#[napi]
pub fn classify_batch(
    commands: Vec<String>,
    context: Option<JsClassifyContext>,
) -> Result<Vec<serde_json::Value>> {
    let ctx = context.map(|c| c.into_core_context());
    let strs: Vec<&str> = commands.iter().map(|s| s.as_str()).collect();
    let results = sh_guard_core::classify_batch(&strs, ctx.as_ref());

    results
        .into_iter()
        .map(|r| serde_json::to_value(&r).map_err(|e| Error::from_reason(format!("{}", e))))
        .collect()
}
