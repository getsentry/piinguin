use std::str::FromStr;

use semaphore_general::pii::BUILTIN_RULES;
use semaphore_general::types::{Annotated, Value};
use serde_json;

use failure::{err_msg, Error};

use types::*;

static PII_KINDS: &[&'static str] = &["text", "container"];

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
            Some(mut x) => x
                .as_object_mut()
                .ok_or_else(|| err_msg("Bad applications value"))?,
            None => return Ok(false),
        };

        let rules_for_kind = match applications.get_mut(pii_kind) {
            Some(mut x) => x
                .as_array_mut()
                .ok_or_else(|| err_msg("Bad PII kind value"))?,
            None => return Ok(false),
        };

        let value = serde_json::Value::String(rule.to_string());

        Ok(match rules_for_kind.iter().position(|x| *x == value) {
            Some(index) => {
                rules_for_kind.remove(index);
                true
            }
            None => false,
        })
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

    for pii_kind in PII_KINDS {
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

        // Removing the key
        if let Some(key) = path.rsplitn(2, '.').next() {
            if !key.is_empty() {
                let mut new_config = old_config.clone();
                let rule = format!("remove_all_{}_keys", key);
                new_config
                    .0
                    .entry("rules")
                    .or_insert(json!({}))
                    .as_object_mut()
                    .ok_or_else(|| err_msg("Bad rules value"))?
                    .insert(
                        rule.clone(),
                        json!({
                            "type": "redact_pair",
                            "keyPattern": key.to_owned()
                        }),
                    );

                if new_config.add_rule(pii_kind, &rule)? && rule_does_something(&new_config) {
                    rv.push(PiiRuleSuggestion::RemoveKey {
                        pii_kind: pii_kind.to_string(),
                        key: key.to_owned(),
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
    RemoveKey {
        pii_kind: String,
        key: String,
        config: PiiConfig,
    },
}
