use std::collections::BTreeMap;
use std::path::Path;

use figment::{
    Figment,
    providers::{Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

// Re-export check config types from the library crate.
pub use yara_x::check_config::CheckConfig;

/// Configuration for the CLI.
#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Configuration for the `fmt` command.
    pub fmt: FormatConfig,
    /// Configuration for the `check` command.
    pub check: CheckConfig,
    /// Configuration for warnings. Keys are warning identifiers
    /// and values are the configuration for that warning.
    pub warnings: BTreeMap<String, WarningConfig>,
}

/// Configuration for the `fmt` command.
#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct FormatConfig {
    /// Rule specific formatting information.
    pub rule: RuleFormatConfig,
    /// Meta specific formatting information.
    pub meta: MetaFormatConfig,
    /// Pattern specific formatting information.
    pub patterns: PatternsFormatConfig,
}

/// Rule specific formatting information.
#[derive(Deserialize, Serialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RuleFormatConfig {
    /// Indent section headers (meta, strings, condition).
    pub indent_section_headers: bool,
    /// Indent section contents one level past section headers.
    pub indent_section_contents: bool,
    /// Number of spaces for indent. Set to 0 to use tabs.
    pub indent_spaces: u8,
    /// Insert a newline after the rule declaration but before the curly brace.
    pub newline_before_curly_brace: bool,
    /// Insert an empty line before section headers.
    pub empty_line_before_section_header: bool,
    /// Insert an empty line after section headers.
    pub empty_line_after_section_header: bool,
}

/// Meta specific formatting information.
#[derive(Deserialize, Serialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct MetaFormatConfig {
    /// Align values to longest key.
    pub align_values: bool,
}

/// Pattern specific formatting information.
#[derive(Deserialize, Serialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PatternsFormatConfig {
    /// Align patterns to the longest name.
    pub align_values: bool,
}

/// Configuration for warnings.
#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct WarningConfig {
    pub disabled: bool,
}

impl Default for RuleFormatConfig {
    fn default() -> RuleFormatConfig {
        RuleFormatConfig {
            indent_section_headers: true,
            indent_section_contents: true,
            indent_spaces: 2,
            newline_before_curly_brace: false,
            empty_line_before_section_header: true,
            empty_line_after_section_header: false,
        }
    }
}

impl Default for MetaFormatConfig {
    fn default() -> MetaFormatConfig {
        MetaFormatConfig { align_values: true }
    }
}

impl Default for PatternsFormatConfig {
    fn default() -> PatternsFormatConfig {
        PatternsFormatConfig { align_values: true }
    }
}

/// Load a config file from a given path. Path must contain a valid TOML file
/// or this function will propagate the error. For structure of the config file
/// see "YARA-X Config Guide.md".
pub fn load_config_from_file(
    config_file: &Path,
) -> Result<Config, Box<figment::Error>> {
    let config: Config =
        Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file_exact(config_file))
            .extract()?;
    Ok(config)
}
