use std::str::FromStr;

use marshal::protocol::{Annotated, Value};
use serde_json;

use failure::{err_msg, Error};

use types::*;

static PII_KINDS: &[&'static str] = &[
    "freeform",
    "ip",
    "id",
    "username",
    "hostname",
    "sensitive",
    "name",
    "email",
    "databag",
];

static BUILTIN_RULES: &[&'static str] = &[
    "@ip:replace",
    "@ip:hash",
    "@imei:replace",
    "@imei:hash",
    "@mac:replace",
    "@mac:mask",
    "@mac:hash",
    "@email:mask",
    "@email:replace",
    "@email:hash",
    "@creditcard:mask",
    "@creditcard:replace",
    "@creditcard:hash",
    "@userpath:replace",
    "@userpath:hash",
    "@password:remove",
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
            Some(Value::Map(map)) => map.get(segment)?,
            _ => return None,
        };

        get_value_by_path(new_value, parts.next().unwrap_or(""))
    }
}

trait PiiConfigExt: Sized {
    fn add_rule(&mut self, pii_kind: &str, rule: &str) -> Result<bool, Error>;
    fn get_known_rules(&self) -> Vec<String>;
}

impl PiiConfigExt for PiiConfig {
    fn add_rule(&mut self, pii_kind: &str, rule: &str) -> Result<bool, Error> {
        let applications = self
            .0
            .entry("applications")
            .or_insert(json!({}))
            .as_object_mut()
            .ok_or(err_msg("Bad applications value"))?;

        let rules_for_kind = applications
            .entry(pii_kind)
            .or_insert(json!([]))
            .as_array_mut()
            .ok_or(err_msg("Bad PII kind value"))?;

        let value = serde_json::Value::String(rule.to_string());
        if !rules_for_kind.contains(&value) {
            rules_for_kind.push(value);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn get_known_rules(&self) -> Vec<String> {
        BUILTIN_RULES
            .iter()
            .map(|x| *x)
            .chain(
                self.0
                    .get("rules")
                    .and_then(|rules_value| rules_value.as_object())
                    .map(|rules_map| rules_map.keys().map(|x| &**x))
                    .into_iter()
                    .flatten(),
            ).map(|x| x.to_string())
            .collect()
    }
}

fn pii_kind_for_path(event: &StrippedEvent, path: &str) -> Result<Option<&'static str>, Error> {
    let mut map = serde_json::Map::new();
    map.insert(
        "rules".to_owned(),
        json!({
        "piinguin_remove_everything": {
            "redaction": {
                "method": "remove"
            },
            "type": "anything"
        }
    }),
    );
    let base_config = PiiConfig(map);
    let old_value = get_value_by_path(event, path);
    let sensitive_event = serde_json::from_value(serde_json::to_value(&event)?)?;

    for pii_kind in PII_KINDS {
        let mut config = base_config.clone();
        config.add_rule(pii_kind, "piinguin_remove_everything")?;
        let new_event = config.strip_event(&sensitive_event)?;
        let value = get_value_by_path(&new_event, path);
        if value != old_value {
            return Ok(Some(pii_kind));
        }
    }
    Ok(None)
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

    if let Some(pii_kind) = pii_kind_for_path(
        &serde_json::from_value(serde_json::to_value(event).unwrap()).unwrap(),
        path,
    )? {
        let rule_does_something = |new_config: &PiiConfig| {
            let new_result = match new_config.strip_event(event) {
                Ok(x) => x,
                Err(_) => return false,
            };

            let new_value = get_value_by_path(&new_result, path).map(|x| x.value());

            new_value != old_value
        };

        for rule in old_config.get_known_rules() {
            let mut new_config = old_config.clone();
            if new_config.add_rule(pii_kind, &rule)? {
                if rule_does_something(&new_config) {
                    rv.push(PiiRuleSuggestion::Value {
                        pii_kind: pii_kind.to_owned(),
                        rule: (*rule).to_owned(),
                        config: new_config,
                    });
                }
            }
        }

        if let Some(key) = path.rsplitn(2, '.').next() {
            if !key.is_empty() {
                let mut new_config = old_config.clone();
                let rule = format!("remove_all_{}_keys", key);
                new_config
                    .0
                    .entry("rules")
                    .or_insert(json!({}))
                    .as_object_mut()
                    .ok_or(err_msg("Bad rules value"))?
                    .insert(
                        rule.clone(),
                        json!({
                        "type": "redactPair",
                        "keyPattern": key.to_owned()
                    }),
                    );

                if new_config.add_rule(pii_kind, &rule)? {
                    if rule_does_something(&new_config) {
                        rv.push(PiiRuleSuggestion::Key {
                            pii_kind: (*pii_kind).to_owned(),
                            key: key.to_owned(),
                            config: new_config,
                        });
                    }
                }
            }
        }
    }

    Ok(rv)
}

#[derive(PartialEq)]
pub enum PiiRuleSuggestion {
    Value {
        pii_kind: String,
        rule: String,
        config: PiiConfig,
    },
    Key {
        pii_kind: String,
        key: String,
        config: PiiConfig,
    },
}