use crate::builtin_tools::is_builtin_tool;
use crate::registry::{ToolDefinition, ToolchainPackRegistry};
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

const SECURITY_AGENT_SKILL: &str = include_str!("../.github/skills/security-agent/SKILL.md");

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
}

impl LocalTool {
    pub fn is_available(&self) -> bool {
        self.built_in || self.executable.is_some()
    }

    pub fn is_installed(&self) -> bool {
        self.executable.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct LocalAgentAssets {
    skills: Vec<LocalSkill>,
    tools: Vec<LocalTool>,
}

impl Default for LocalAgentAssets {
    fn default() -> Self {
        Self::bundled()
    }
}

impl LocalAgentAssets {
    pub fn bundled() -> Self {
        let skills = vec![LocalSkill {
            name: "security-agent",
            content: SECURITY_AGENT_SKILL,
        }];

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
        let tools = definitions
            .into_values()
            .map(|definition| LocalTool {
                built_in: is_builtin_tool(&definition.name),
                executable: find_executable(&definition.name),
                definition,
            })
            .collect();

        Self { skills, tools }
    }

    pub fn skills(&self) -> &[LocalSkill] {
        &self.skills
    }

    pub fn skill(&self, name: &str) -> Option<&LocalSkill> {
        self.skills.iter().find(|skill| skill.name == name)
    }

    pub fn tools(&self) -> &[LocalTool] {
        &self.tools
    }

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

        assert!(skill.content.contains("Plan defensive security work"));
        assert!(skill.content.contains("runtime: offline"));
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
