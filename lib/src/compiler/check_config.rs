//! Configuration types and logic for the `check` linting system.
//!
//! This module contains the [`CheckConfig`] struct and the
//! [`apply_check_config`] function, which translates a check configuration
//! into linter instances added to a [`Compiler`].
//!
//! The configuration types use `serde` for deserialization, allowing them to
//! be loaded from TOML, JSON, or any other format supported by serde.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};
use yara_x_parser::ast::MetaValue;

use crate::Compiler;
use crate::compiler::linters;

/// Types allowed for metadata values in a check configuration.
#[derive(Display, Deserialize, Serialize, Debug, Clone, EnumString)]
#[serde(deny_unknown_fields)]
pub enum MetaValueType {
    /// Represents a String type
    #[serde(rename = "string")]
    #[strum(serialize = "string")]
    String,
    #[serde(rename = "integer")]
    #[strum(serialize = "integer")]
    Integer,
    #[serde(rename = "float")]
    #[strum(serialize = "float")]
    Float,
    #[serde(rename = "bool")]
    #[strum(serialize = "bool")]
    Bool,
    #[serde(rename = "sha256")]
    #[strum(serialize = "sha256")]
    Sha256,
    #[serde(rename = "sha1")]
    #[strum(serialize = "sha1")]
    Sha1,
    #[serde(rename = "md5")]
    #[strum(serialize = "md5")]
    MD5,
    #[serde(rename = "hash")]
    #[strum(serialize = "hash")]
    Hash,
}

/// Configuration for the `check` command.
#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct CheckConfig {
    /// Meta specific linting information.
    // Note: Using a BTreeMap here because we want a consistent ordering when
    // we iterate over it, so that warnings always appear in the same order.
    pub metadata: BTreeMap<String, MetadataConfig>,
    /// Rule name linting information.
    pub rule_name: RuleNameConfig,
    /// Tag linting information.
    pub tags: TagConfig,
}

/// Allowed tag names in the linter.
#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct TagConfig {
    /// List of allowed tags.
    pub allowed: Vec<String>,
    /// Regexp that must match all tags.
    pub regexp: Option<String>,
    /// If `true`, an incorrect tag name will raise an error instead of a
    /// warning.
    #[serde(default)]
    pub error: bool,
}

/// Rule name linter specific configuration information.
#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleNameConfig {
    /// Regexp used to validate the rule name.
    pub regexp: Option<String>,
    /// If `true`, an incorrect rule name will raise an error instead of a
    /// warning.
    #[serde(default)]
    pub error: bool,
}

/// Metadata linter specific configuration information.
#[derive(Deserialize, Serialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct MetadataConfig {
    /// The expected type of the metadata value.
    #[serde(rename = "type")]
    pub ty: MetaValueType,
    /// A regular expression that the metadata value must match. Only
    /// applies if type is MetaValueType::String.
    pub regexp: Option<String>,
    /// Specifies whether the metadata is required or optional.
    #[serde(default)]
    pub required: bool,
    /// If `true`, an incorrect metadata will raise an error instead of a
    /// warning.
    #[serde(default)]
    pub error: bool,
}

/// Returns `true` if the string is a valid SHA-256 hash.
pub fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Returns `true` if the string is a valid SHA-1 hash.
pub fn is_sha1(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Returns `true` if the string is a valid MD5 hash.
pub fn is_md5(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Applies a [`CheckConfig`] to a [`Compiler`], adding linters for
/// metadata, rule names, and tags based on the configuration.
///
/// # Errors
///
/// Returns a [`regex::Error`] if any of the regular expressions in the
/// configuration are invalid.
pub fn apply_check_config(
    compiler: &mut Compiler,
    config: &CheckConfig,
) -> Result<(), regex::Error> {
    // Add metadata linters.
    for (identifier, meta_config) in config.metadata.iter() {
        let mut linter = linters::metadata(identifier)
            .required(meta_config.required)
            .error(meta_config.error);

        match meta_config.ty {
            MetaValueType::String => {
                // Clone the regexp so the closure owns it.
                let regexp = meta_config.regexp.clone();
                let message = if let Some(ref re) = regexp {
                    // Validate the regexp early.
                    let _ = regex::bytes::Regex::new(re)?;
                    format!(
                        "`{identifier}` must be a string that matches `/{re}/`"
                    )
                } else {
                    format!("`{identifier}` must be a string")
                };
                linter = linter.validator(
                    move |meta| match (&meta.value, &regexp) {
                        (MetaValue::String((s, _)), Some(regexp)) => {
                            regex::Regex::new(regexp).unwrap().is_match(s)
                        }
                        (MetaValue::Bytes((s, _)), Some(regexp)) => {
                            regex::bytes::Regex::new(regexp)
                                .unwrap()
                                .is_match(s)
                        }
                        (MetaValue::String(_), None) => true,
                        (MetaValue::Bytes(_), None) => true,
                        _ => false,
                    },
                    message,
                );
            }
            MetaValueType::Integer => {
                linter = linter.validator(
                    |meta| matches!(meta.value, MetaValue::Integer(_)),
                    format!("`{identifier}` must be an integer"),
                );
            }
            MetaValueType::Float => {
                linter = linter.validator(
                    |meta| matches!(meta.value, MetaValue::Float(_)),
                    format!("`{identifier}` must be a float"),
                );
            }
            MetaValueType::Bool => {
                linter = linter.validator(
                    |meta| matches!(meta.value, MetaValue::Bool(_)),
                    format!("`{identifier}` must be a bool"),
                );
            }
            MetaValueType::Sha256 => {
                linter = linter.validator(
                    |meta| {
                        matches!(meta.value, MetaValue::String((s,_)) if is_sha256(s))
                    },
                    format!("`{identifier}` must be a SHA-256"),
                );
            }
            MetaValueType::Sha1 => {
                linter = linter.validator(
                    |meta| {
                        matches!(meta.value, MetaValue::String((s,_)) if is_sha1(s))
                    },
                    format!("`{identifier}` must be a SHA-1"),
                );
            }
            MetaValueType::MD5 => {
                linter = linter.validator(
                    |meta| {
                        matches!(meta.value, MetaValue::String((s,_)) if is_md5(s))
                    },
                    format!("`{identifier}` must be a MD5"),
                );
            }
            MetaValueType::Hash => {
                linter = linter.validator(
                    |meta| {
                        matches!(meta.value, MetaValue::String((s,_))
                            if is_md5(s) || is_sha1(s) || is_sha256(s))
                    },
                    format!(
                        "`{identifier}` must be a MD5, SHA-1 or SHA-256"
                    ),
                );
            }
        }

        compiler.add_linter(linter);
    }

    // Add rule name linter.
    if let Some(re) = config
        .rule_name
        .regexp
        .as_ref()
        .filter(|re| !re.is_empty())
    {
        compiler
            .add_linter(linters::rule_name(re)?.error(config.rule_name.error));
    }

    // Add tag linters. Prefer allowed list over the regex, as it is more
    // explicit.
    if !config.tags.allowed.is_empty() {
        compiler.add_linter(
            linters::tags_allowed(config.tags.allowed.clone())
                .error(config.tags.error),
        );
    } else if let Some(re) =
        config.tags.regexp.as_ref().filter(|re| !re.is_empty())
    {
        compiler
            .add_linter(linters::tag_regex(re)?.error(config.tags.error));
    }

    Ok(())
}
