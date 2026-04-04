use crate::types::BinaryCapability;

pub struct GtfobinEntry {
    pub name: &'static str,
    pub capabilities: &'static [BinaryCapability],
}

/// Top dangerous binaries from GTFOBins with their abuse capabilities.
pub static GTFOBINS: &[GtfobinEntry] = &[
    // --- Can spawn shells ---
    GtfobinEntry {
        name: "vim",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::FileRead,
            BinaryCapability::FileWrite,
        ],
    },
    GtfobinEntry {
        name: "vi",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::FileRead,
            BinaryCapability::FileWrite,
        ],
    },
    GtfobinEntry {
        name: "nano",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::FileRead,
            BinaryCapability::FileWrite,
        ],
    },
    GtfobinEntry {
        name: "emacs",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::FileRead,
            BinaryCapability::FileWrite,
            BinaryCapability::Command,
        ],
    },
    GtfobinEntry {
        name: "less",
        capabilities: &[BinaryCapability::Shell, BinaryCapability::FileRead],
    },
    GtfobinEntry {
        name: "more",
        capabilities: &[BinaryCapability::Shell, BinaryCapability::FileRead],
    },
    GtfobinEntry {
        name: "man",
        capabilities: &[BinaryCapability::Shell],
    },
    GtfobinEntry {
        name: "ftp",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::Upload,
            BinaryCapability::Download,
        ],
    },
    GtfobinEntry {
        name: "gdb",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::Command,
            BinaryCapability::FileRead,
            BinaryCapability::FileWrite,
        ],
    },
    GtfobinEntry {
        name: "nmap",
        capabilities: &[BinaryCapability::Shell, BinaryCapability::Command],
    },
    GtfobinEntry {
        name: "awk",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::Command,
            BinaryCapability::FileRead,
        ],
    },
    GtfobinEntry {
        name: "gawk",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::Command,
            BinaryCapability::FileRead,
        ],
    },
    // --- Can execute arbitrary commands ---
    GtfobinEntry {
        name: "find",
        capabilities: &[BinaryCapability::Command, BinaryCapability::Shell],
    },
    GtfobinEntry {
        name: "xargs",
        capabilities: &[BinaryCapability::Command],
    },
    GtfobinEntry {
        name: "tar",
        capabilities: &[
            BinaryCapability::Command,
            BinaryCapability::FileRead,
            BinaryCapability::FileWrite,
        ],
    },
    GtfobinEntry {
        name: "zip",
        capabilities: &[BinaryCapability::Command, BinaryCapability::FileRead],
    },
    GtfobinEntry {
        name: "expect",
        capabilities: &[BinaryCapability::Shell, BinaryCapability::Command],
    },
    GtfobinEntry {
        name: "strace",
        capabilities: &[BinaryCapability::Command],
    },
    GtfobinEntry {
        name: "ltrace",
        capabilities: &[BinaryCapability::Command],
    },
    GtfobinEntry {
        name: "nice",
        capabilities: &[BinaryCapability::Command],
    },
    GtfobinEntry {
        name: "time",
        capabilities: &[BinaryCapability::Command],
    },
    GtfobinEntry {
        name: "timeout",
        capabilities: &[BinaryCapability::Command],
    },
    GtfobinEntry {
        name: "watch",
        capabilities: &[BinaryCapability::Command],
    },
    GtfobinEntry {
        name: "env",
        capabilities: &[BinaryCapability::Command],
    },
    GtfobinEntry {
        name: "crontab",
        capabilities: &[BinaryCapability::Command],
    },
    GtfobinEntry {
        name: "at",
        capabilities: &[BinaryCapability::Command],
    },
    // --- File read ---
    GtfobinEntry {
        name: "curl",
        capabilities: &[
            BinaryCapability::Download,
            BinaryCapability::Upload,
            BinaryCapability::FileRead,
        ],
    },
    GtfobinEntry {
        name: "wget",
        capabilities: &[BinaryCapability::Download, BinaryCapability::FileWrite],
    },
    GtfobinEntry {
        name: "dd",
        capabilities: &[BinaryCapability::FileRead, BinaryCapability::FileWrite],
    },
    GtfobinEntry {
        name: "base64",
        capabilities: &[BinaryCapability::FileRead],
    },
    GtfobinEntry {
        name: "xxd",
        capabilities: &[BinaryCapability::FileRead, BinaryCapability::FileWrite],
    },
    GtfobinEntry {
        name: "od",
        capabilities: &[BinaryCapability::FileRead],
    },
    GtfobinEntry {
        name: "hexdump",
        capabilities: &[BinaryCapability::FileRead],
    },
    GtfobinEntry {
        name: "strings",
        capabilities: &[BinaryCapability::FileRead],
    },
    GtfobinEntry {
        name: "diff",
        capabilities: &[BinaryCapability::FileRead],
    },
    GtfobinEntry {
        name: "head",
        capabilities: &[BinaryCapability::FileRead],
    },
    GtfobinEntry {
        name: "tail",
        capabilities: &[BinaryCapability::FileRead],
    },
    GtfobinEntry {
        name: "sort",
        capabilities: &[BinaryCapability::FileRead],
    },
    // --- File write ---
    GtfobinEntry {
        name: "tee",
        capabilities: &[BinaryCapability::FileWrite],
    },
    GtfobinEntry {
        name: "cp",
        capabilities: &[BinaryCapability::FileWrite],
    },
    GtfobinEntry {
        name: "mv",
        capabilities: &[BinaryCapability::FileWrite],
    },
    GtfobinEntry {
        name: "install",
        capabilities: &[BinaryCapability::FileWrite],
    },
    GtfobinEntry {
        name: "sed",
        capabilities: &[BinaryCapability::FileRead, BinaryCapability::FileWrite],
    },
    // --- Network ---
    GtfobinEntry {
        name: "ssh",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::Command,
            BinaryCapability::Upload,
            BinaryCapability::Download,
        ],
    },
    GtfobinEntry {
        name: "scp",
        capabilities: &[BinaryCapability::Upload, BinaryCapability::Download],
    },
    GtfobinEntry {
        name: "nc",
        capabilities: &[
            BinaryCapability::ReverseShell,
            BinaryCapability::BindShell,
            BinaryCapability::Upload,
            BinaryCapability::Download,
        ],
    },
    GtfobinEntry {
        name: "ncat",
        capabilities: &[
            BinaryCapability::ReverseShell,
            BinaryCapability::BindShell,
            BinaryCapability::Upload,
            BinaryCapability::Download,
        ],
    },
    GtfobinEntry {
        name: "socat",
        capabilities: &[
            BinaryCapability::ReverseShell,
            BinaryCapability::BindShell,
            BinaryCapability::Upload,
            BinaryCapability::Download,
            BinaryCapability::Shell,
        ],
    },
    GtfobinEntry {
        name: "rsync",
        capabilities: &[
            BinaryCapability::Upload,
            BinaryCapability::Download,
            BinaryCapability::Command,
        ],
    },
    GtfobinEntry {
        name: "openssl",
        capabilities: &[
            BinaryCapability::ReverseShell,
            BinaryCapability::FileRead,
            BinaryCapability::FileWrite,
        ],
    },
    GtfobinEntry {
        name: "telnet",
        capabilities: &[BinaryCapability::ReverseShell],
    },
    // --- Reverse shell ---
    GtfobinEntry {
        name: "python",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::Command,
            BinaryCapability::ReverseShell,
            BinaryCapability::FileRead,
            BinaryCapability::FileWrite,
            BinaryCapability::Download,
        ],
    },
    GtfobinEntry {
        name: "python3",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::Command,
            BinaryCapability::ReverseShell,
            BinaryCapability::FileRead,
            BinaryCapability::FileWrite,
            BinaryCapability::Download,
        ],
    },
    GtfobinEntry {
        name: "perl",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::Command,
            BinaryCapability::ReverseShell,
            BinaryCapability::FileRead,
            BinaryCapability::FileWrite,
        ],
    },
    GtfobinEntry {
        name: "ruby",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::Command,
            BinaryCapability::ReverseShell,
            BinaryCapability::FileRead,
            BinaryCapability::FileWrite,
        ],
    },
    GtfobinEntry {
        name: "php",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::Command,
            BinaryCapability::ReverseShell,
            BinaryCapability::FileRead,
            BinaryCapability::FileWrite,
        ],
    },
    GtfobinEntry {
        name: "node",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::Command,
            BinaryCapability::ReverseShell,
            BinaryCapability::FileRead,
            BinaryCapability::FileWrite,
        ],
    },
    GtfobinEntry {
        name: "lua",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::Command,
            BinaryCapability::FileRead,
        ],
    },
    // --- Privilege escalation (when SUID/sudo) ---
    GtfobinEntry {
        name: "docker",
        capabilities: &[
            BinaryCapability::Shell,
            BinaryCapability::PrivilegeEscalation,
            BinaryCapability::FileRead,
            BinaryCapability::FileWrite,
        ],
    },
    GtfobinEntry {
        name: "pkexec",
        capabilities: &[
            BinaryCapability::PrivilegeEscalation,
            BinaryCapability::Command,
        ],
    },
    GtfobinEntry {
        name: "doas",
        capabilities: &[
            BinaryCapability::PrivilegeEscalation,
            BinaryCapability::Command,
        ],
    },
    // --- Library loading ---
    GtfobinEntry {
        name: "ld.so",
        capabilities: &[BinaryCapability::LibraryLoad, BinaryCapability::Command],
    },
];

/// Look up GTFOBins capabilities for a binary.
pub fn lookup_capabilities(name: &str) -> &'static [BinaryCapability] {
    let base = name.rsplit('/').next().unwrap_or(name);
    GTFOBINS
        .iter()
        .find(|e| e.name == base)
        .map(|e| e.capabilities)
        .unwrap_or(&[])
}
