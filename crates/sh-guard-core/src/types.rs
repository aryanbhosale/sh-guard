use serde::{Deserialize, Serialize};

// --- Input Types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifyContext {
    pub cwd: Option<String>,
    pub project_root: Option<String>,
    pub home_dir: Option<String>,
    #[serde(default)]
    pub protected_paths: Vec<String>,
    #[serde(default)]
    pub shell: Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Shell {
    #[default]
    Bash,
    Zsh,
}

// --- Output Types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub command: String,
    pub score: u8,
    pub level: RiskLevel,
    pub quick_decision: QuickDecision,
    pub reason: String,
    pub risk_factors: Vec<RiskFactor>,
    pub sub_commands: Vec<CommandAnalysis>,
    pub pipeline_flow: Option<PipelineFlow>,
    pub mitre_mappings: Vec<MitreMapping>,
    pub parse_confidence: ParseConfidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Safe,     // 0-20
    Caution,  // 21-50
    Danger,   // 51-80
    Critical, // 81-100
}

impl RiskLevel {
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=20 => RiskLevel::Safe,
            21..=50 => RiskLevel::Caution,
            51..=80 => RiskLevel::Danger,
            _ => RiskLevel::Critical,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuickDecision {
    Safe,
    Risky,
    Blocked,
}

impl QuickDecision {
    pub fn from_level(level: RiskLevel) -> Self {
        match level {
            RiskLevel::Safe => QuickDecision::Safe,
            RiskLevel::Caution | RiskLevel::Danger => QuickDecision::Risky,
            RiskLevel::Critical => QuickDecision::Blocked,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandAnalysis {
    pub command: String,
    pub executable: Option<String>,
    pub intent: Vec<Intent>,
    pub targets: Vec<Target>,
    pub flags: Vec<FlagAnalysis>,
    pub score: u8,
    pub risk_factors: Vec<RiskFactor>,
    pub reversibility: Reversibility,
    pub capabilities: Vec<BinaryCapability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    Read,
    Write,
    Delete,
    Execute,
    Network,
    ProcessControl,
    Privilege,
    PackageInstall,
    GitMutation,
    EnvModify,
    Search,
    Info,
}

impl Intent {
    pub fn weight(&self) -> u8 {
        match self {
            Intent::Info => 0,
            Intent::Search => 5,
            Intent::Read => 10,
            Intent::Write => 30,
            Intent::PackageInstall => 35,
            Intent::GitMutation => 35,
            Intent::EnvModify => 40,
            Intent::Network => 40,
            Intent::ProcessControl => 40,
            Intent::Delete => 45,
            Intent::Execute => 50,
            Intent::Privilege => 55,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub path: Option<String>,
    pub scope: TargetScope,
    pub sensitivity: Sensitivity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetScope {
    None,
    SingleFile,
    Directory,
    DirectoryRecursive,
    System,
    Home,
    Root,
}

impl TargetScope {
    pub fn modifier(&self) -> i16 {
        match self {
            TargetScope::None | TargetScope::SingleFile => 0,
            TargetScope::Directory => 5,
            TargetScope::DirectoryRecursive => 15,
            TargetScope::System => 25,
            TargetScope::Home => 30,
            TargetScope::Root => 40,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Normal,
    Config,
    System,
    Secrets,
    Protected,
}

impl Sensitivity {
    pub fn modifier(&self) -> i16 {
        match self {
            Sensitivity::Normal => 0,
            Sensitivity::Config => 10,
            Sensitivity::System => 20,
            Sensitivity::Secrets => 25,
            Sensitivity::Protected => 25,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    Reversible,
    HardToReverse,
    Irreversible,
}

impl Reversibility {
    pub fn modifier(&self) -> i16 {
        match self {
            Reversibility::Reversible => -10,
            Reversibility::HardToReverse => 5,
            Reversibility::Irreversible => 15,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryCapability {
    Shell,
    Command,
    ReverseShell,
    BindShell,
    FileRead,
    FileWrite,
    Upload,
    Download,
    LibraryLoad,
    PrivilegeEscalation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFactor {
    RecursiveDelete,
    ForceFlag,
    BroadScope,
    SecretsExposure,
    NetworkExfiltration,
    PipeToExecution,
    CommandSubstitution,
    ProcessSubstitution,
    UntrustedExecution,
    PrivilegeEscalation,
    PathInjection,
    GitHistoryDestruction,
    EscapesProjectBoundary,
    ShellInjection,
    ZshModuleLoading,
    ZshGlobExecution,
    ObfuscatedCommand,
    ObfuscatedExfiltration,
    CommandExecution,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagAnalysis {
    pub flag: String,
    pub modifier: i8,
    pub risk_factor: RiskFactor,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineFlow {
    pub flow_type: FlowType,
    pub taint_flows: Vec<TaintFlow>,
    pub composite_score: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowType {
    Pipe,
    And,
    Or,
    Sequence,
    Mixed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    pub source: TaintSource,
    pub propagators: Vec<TaintProp>,
    pub sink: TaintSink,
    pub escalation: u8,
    pub escalation_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum TaintSource {
    SensitiveFile { path: String },
    EnvironmentVar,
    CommandOutput,
    Stdin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintProp {
    Passthrough,
    Encoding { method: String },
    Filtering,
    Aggregation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum TaintSink {
    NetworkSend,
    FileWrite { path: String },
    Execution,
    Display,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseConfidence {
    Full,
    Partial,
    Fallback,
}
