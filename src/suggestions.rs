use std::str::FromStr;

use relay_general::pii::BUILTIN_RULES;
use relay_general::types::{Annotated, Value};
use serde_json;

use failure::{err_msg, Error};

use types::*;

static PII_KINDS: &[&'static str] = &[
    "**",
    "$string",
    "$number",
    "$boolean",
    "$datetime",
    "$array",
    "$object",
    "$event",
    "$exception",
    "$stacktrace",
    "$frame",
    "$request",
    "$user",
    "$logentry",
    "$thread",
    "$breadcrumb",
    "$span",
    "$sdk",
];

fn get_value_by_path<'a>(value: &'a Annotated<Value>, path: &str) -> Option<&'a Annotated<Value>> {
    if path.is_empty() || path == "." {
        Some(value)
    } else {
        let mut parts = path.splitn(2, '.');
        let segment = parts.next().unwrap();
        assert!(!segment.is_empty());

        let new_value = match value.value() {
            Some(Value::Array(array)) => array.get(usize::from_str(segment).ok()?)?,
            Some(Value::Object(map)) => map.get(segment)?,
            _ => return None,
        };

        get_value_by_path(new_value, parts.next().unwrap_or(""))
    }
}

trait PiiConfigExt: Sized {
    fn add_rule(&mut self, pii_kind: &str, rule: &str) -> Result<bool, Error>;
    fn remove_rule(&mut self, pii_kind: &str, rule: &str) -> Result<bool, Error>;
    fn get_known_rules(&self) -> Vec<String>;
}

impl PiiConfigExt for PiiConfig {
    fn add_rule(&mut self, pii_kind: &str, rule: &str) -> Result<bool, Error> {
        let applications = self
            .0
            .entry("applications")
            .or_insert(json!({}))
            .as_object_mut()
            .ok_or_else(|| err_msg("Bad applications value"))?;

        let rules_for_kind = applications
            .entry(pii_kind)
            .or_insert(json!([]))
            .as_array_mut()
            .ok_or_else(|| err_msg("Bad PII kind value"))?;

        let value = serde_json::Value::String(rule.to_string());
        if !rules_for_kind.contains(&value) {
            rules_for_kind.push(value);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn remove_rule(&mut self, pii_kind: &str, rule: &str) -> Result<bool, Error> {
        let applications = match self.0.get_mut("applications") {
            Some(x) => x
                .as_object_mut()
                .ok_or_else(|| err_msg("Bad applications value"))?,
            None => return Ok(false),
        };

        let rules_for_kind = match applications.get_mut(pii_kind) {
            Some(x) => x
                .as_array_mut()
                .ok_or_else(|| err_msg("Bad PII kind value"))?,
            None => return Ok(false),
        };

        let value = serde_json::Value::String(rule.to_string());

        match rules_for_kind.iter().position(|x| *x == value) {
            Some(index) => {
                rules_for_kind.remove(index);
            }
            None => return Ok(false),
        }

        let should_remove = rules_for_kind.is_empty();

        if should_remove {
            applications.remove(pii_kind);
        }

        Ok(true)
    }

    fn get_known_rules(&self) -> Vec<String> {
        BUILTIN_RULES
            .iter()
            .cloned()
            .chain(
                self.0
                    .get("rules")
                    .and_then(|rules_value| rules_value.as_object())
                    .map(|rules_map| rules_map.keys().map(|x| &**x))
                    .into_iter()
                    .flatten(),
            )
            .map(|x| x.to_string())
            .collect()
    }
}

pub fn get_rule_suggestions_for_value(
    event: &SensitiveEvent,
    old_config: &PiiConfig,
    path: &str,
) -> Result<Vec<PiiRuleSuggestion>, Error> {
    let old_result = old_config.strip_event(event)?;
    let old_value = get_value_by_path(&old_result, path).map(|x| x.value());

    let mut rv = vec![];

    println!("Old value: {:?}", old_value);

    let rule_does_something = |new_config: &PiiConfig| {
        let new_result = match new_config.strip_event(event) {
            Ok(x) => x,
            Err(_) => return false,
        };

        let new_value = get_value_by_path(&new_result, path).map(|x| x.value());

        new_value != old_value
    };

    for pii_kind in PII_KINDS.iter().chain(&[path]) {
        let known_rules = old_config.get_known_rules();

        for rule in &known_rules {
            let mut new_config = old_config.clone();
            if new_config.add_rule(pii_kind, &rule)? {
                // Adding a rule for the value
                if rule_does_something(&new_config) {
                    rv.push(PiiRuleSuggestion::ActivateRule {
                        pii_kind: pii_kind.to_string(),
                        rule: (*rule).to_owned(),
                        config: new_config,
                    });
                }
            }

            let mut new_config = old_config.clone();
            if new_config.remove_rule(pii_kind, &rule)? {
                // Removing a rule for the value
                if rule_does_something(&new_config) {
                    rv.push(PiiRuleSuggestion::DeactivateRule {
                        pii_kind: pii_kind.to_string(),
                        rule: (*rule).to_owned(),
                        config: new_config,
                    });
                }
            }
        }
    }

    Ok(rv)
}

#[derive(PartialEq)]
pub enum PiiRuleSuggestion {
    ActivateRule {
        pii_kind: String,
        rule: String,
        config: PiiConfig,
    },
    DeactivateRule {
        pii_kind: String,
        rule: String,
        config: PiiConfig,
    },
}

impl PiiRuleSuggestion {
    pub fn pii_kind(&self) -> &str {
        match *self {
            PiiRuleSuggestion::ActivateRule { ref pii_kind, .. } => pii_kind,
            PiiRuleSuggestion::DeactivateRule { ref pii_kind, .. } => pii_kind,
        }
    }
}
