use crate::builtin_tools::is_builtin_tool;
use crate::integrity::{IntegrityManifest, IntegrityStatus, verify};
use crate::registry::{ToolDefinition, ToolchainPackRegistry};
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

const SECURITY_AGENT_SKILL: &str = include_str!("../.github/skills/security-agent/SKILL.md");

/// Builds a [`LocalSkill`] for a cataloged tool from its
/// `.github/skills/<name>/SKILL.md` file, compiled into the binary.
macro_rules! tool_skill {
    ($name:literal) => {
        LocalSkill {
            name: $name,
            content: include_str!(concat!("../.github/skills/", $name, "/SKILL.md")),
        }
    };
}

/// One embedded skill per cataloged tool (see `src/registry.rs`), covering
/// its execution class, specialist approval, and authorization
/// requirements. Kept in sync with the tool catalog by
/// `tool_skills_cover_every_cataloged_tool` in this module's tests.
fn tool_skills() -> Vec<LocalSkill> {
    vec![
        tool_skill!("aircrack-ng"),
        tool_skill!("amass"),
        tool_skill!("androguard"),
        tool_skill!("apkleaks"),
        tool_skill!("apksigner"),
        tool_skill!("apktool"),
        tool_skill!("autopsy"),
        tool_skill!("beef-xss"),
        tool_skill!("bettercap"),
        tool_skill!("binwalk"),
        tool_skill!("bulk_extractor"),
        tool_skill!("burpsuite"),
        tool_skill!("cewl"),
        tool_skill!("chirpw"),
        tool_skill!("chkrootkit"),
        tool_skill!("crackmapexec"),
        tool_skill!("crunch"),
        tool_skill!("cutycapt"),
        tool_skill!("dex2jar"),
        tool_skill!("dirb"),
        tool_skill!("dmitry"),
        tool_skill!("driftnet"),
        tool_skill!("drozer"),
        tool_skill!("enum4linux"),
        tool_skill!("ettercap"),
        tool_skill!("evil-winrm"),
        tool_skill!("feroxbuster"),
        tool_skill!("ffuf"),
        tool_skill!("foremost"),
        tool_skill!("frida"),
        tool_skill!("galleta"),
        tool_skill!("giskismet"),
        tool_skill!("gobuster"),
        tool_skill!("hashcat"),
        tool_skill!("hashdeep"),
        tool_skill!("httrack"),
        tool_skill!("hydra"),
        tool_skill!("ike-scan"),
        tool_skill!("jadx"),
        tool_skill!("john"),
        tool_skill!("keepnote"),
        tool_skill!("kismet"),
        tool_skill!("lynis"),
        tool_skill!("macchanger"),
        tool_skill!("mariana-trench"),
        tool_skill!("masscan"),
        tool_skill!("mdb-sql"),
        tool_skill!("medusa"),
        tool_skill!("mfoc"),
        tool_skill!("mfterm"),
        tool_skill!("mitmproxy"),
        tool_skill!("mobsf"),
        tool_skill!("msfconsole"),
        tool_skill!("msfpc"),
        tool_skill!("ncrack"),
        tool_skill!("netdiscover"),
        tool_skill!("netexec"),
        tool_skill!("netsniff-ng"),
        tool_skill!("nikto"),
        tool_skill!("nmap"),
        tool_skill!("nuclei"),
        tool_skill!("objection"),
        tool_skill!("ophcrack"),
        tool_skill!("pyrit"),
        tool_skill!("qark"),
        tool_skill!("rcrack"),
        tool_skill!("reaver"),
        tool_skill!("recordmydesktop"),
        tool_skill!("searchsploit"),
        tool_skill!("semgrep"),
        tool_skill!("setoolkit"),
        tool_skill!("skipfish"),
        tool_skill!("smbmap"),
        tool_skill!("sqlitebrowser"),
        tool_skill!("sqlmap"),
        tool_skill!("subfinder"),
        tool_skill!("tcpdump"),
        tool_skill!("termineter"),
        tool_skill!("thc-ipv6"),
        tool_skill!("trueseeing"),
        tool_skill!("volatility"),
        tool_skill!("wafw00f"),
        tool_skill!("wfuzz"),
        tool_skill!("whatweb"),
        tool_skill!("wifite"),
        tool_skill!("wireshark"),
        tool_skill!("wpscan"),
        tool_skill!("yersinia"),
        tool_skill!("zenmap"),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalSkill {
    pub name: &'static str,
    pub content: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTool {
    pub definition: ToolDefinition,
    pub built_in: bool,
    pub executable: Option<PathBuf>,
    /// Runtime integrity of the resolved binary against the bundled
    /// manifest (see `crate::integrity`). `Unpinned` for every tool while
    /// the shipped manifest is empty.
    pub integrity: IntegrityStatus,
}

impl LocalTool {
    #[must_use]
    pub const fn is_available(&self) -> bool {
        self.built_in || self.executable.is_some()
    }

    #[must_use]
    pub const fn is_installed(&self) -> bool {
        self.executable.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct LocalAgentAssets {
    pub(crate) skills: Vec<LocalSkill>,
    pub(crate) tools: Vec<LocalTool>,
}

impl Default for LocalAgentAssets {
    fn default() -> Self {
        Self::bundled()
    }
}

impl LocalAgentAssets {
    #[must_use]
    pub fn bundled() -> Self {
        let mut skills = vec![LocalSkill {
            name: "security-agent",
            content: SECURITY_AGENT_SKILL,
        }];
        skills.extend(tool_skills());

        let registry = ToolchainPackRegistry::default();
        let definitions = registry
            .packs
            .values()
            .flat_map(|pack| pack.tools.iter())
            .fold(BTreeMap::new(), |mut tools, definition| {
                tools
                    .entry(definition.name.clone())
                    .or_insert_with(|| definition.clone());
                tools
            });
        let manifest = IntegrityManifest::bundled();
        let tools = definitions
            .into_values()
            .map(|definition| {
                let executable = find_executable(&definition.name);
                LocalTool {
                    built_in: is_builtin_tool(&definition.name),
                    integrity: verify(&definition.name, executable.as_deref(), &manifest),
                    executable,
                    definition,
                }
            })
            .collect();

        Self { skills, tools }
    }

    #[must_use]
    pub fn skills(&self) -> &[LocalSkill] {
        &self.skills
    }

    #[must_use]
    pub fn skill(&self, name: &str) -> Option<&LocalSkill> {
        self.skills.iter().find(|skill| skill.name == name)
    }

    #[must_use]
    pub fn tools(&self) -> &[LocalTool] {
        &self.tools
    }

    #[must_use]
    pub fn tool(&self, name: &str) -> Option<&LocalTool> {
        self.tools.iter().find(|tool| tool.definition.name == name)
    }
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;

    for directory in env::split_paths(&path) {
        let candidate = directory.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }

        #[cfg(windows)]
        for extension in executable_extensions() {
            let candidate = directory.join(format!("{name}{extension}"));
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }

    None
}

fn is_executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
    }

    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(windows)]
fn executable_extensions() -> Vec<String> {
    env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string())
        .split(';')
        .map(str::to_ascii_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_skill_is_compiled_into_binary() {
        let assets = LocalAgentAssets::bundled();
        let skill = assets
            .skill("security-agent")
            .expect("security-agent skill should be bundled");

        assert!(
            skill
                .content
                .contains("Plan defensive and offensive security work")
        );
        assert!(skill.content.contains("runtime: offline"));
    }

    #[test]
    fn tool_skills_cover_every_cataloged_tool() {
        let assets = LocalAgentAssets::bundled();

        assert_eq!(
            assets.skills().len(),
            90,
            "one general skill plus one per cataloged tool"
        );

        for tool in assets.tools() {
            let name = &tool.definition.name;
            let skill = assets
                .skill(name)
                .unwrap_or_else(|| panic!("missing skill for cataloged tool: {name}"));
            assert!(
                skill.content.contains(name.as_str()),
                "skill for {name} should mention the tool name"
            );
            assert!(
                skill.content.contains("execution_class"),
                "skill for {name} should document its execution class"
            );
        }
    }

    #[test]
    fn local_tool_catalog_is_deduplicated_and_queryable() {
        let assets = LocalAgentAssets::bundled();
        let names = assets
            .tools()
            .iter()
            .map(|tool| tool.definition.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(assets.tools().len(), 89);
        assert!(assets.tool("nmap").is_some());
        assert!(assets.tool("autopsy").is_some_and(|tool| tool.built_in));
        assert!(assets.tools().iter().all(|tool| {
            tool.definition.version == "not-detected"
                && !tool.definition.signed
                && !tool.definition.vulnerability_reviewed
                && tool.definition.egress_policy == ["offline-local-only"]
        }));
        assert_eq!(
            names.iter().filter(|name| **name == "nmap").count(),
            1,
            "tools shared by packs should appear once"
        );
    }
}
