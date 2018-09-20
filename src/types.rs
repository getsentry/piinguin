use marshal::processor::PiiConfig as ProcessorPiiConfig;
use marshal::protocol::{Annotated, Event, Value};

use failure::{Error, ResultExt};

use serde_json;

pub type SensitiveEvent = Annotated<Event>;
pub type StrippedEvent = Annotated<Value>;

#[derive(Clone, Debug, PartialEq)]
pub struct PiiConfig(pub serde_json::Map<String, serde_json::Value>);

impl From<ProcessorPiiConfig> for PiiConfig {
    fn from(config: ProcessorPiiConfig) -> PiiConfig {
        PiiConfig(serde_json::from_str(&config.to_json().unwrap()).unwrap())
    }
}

impl From<PiiConfig> for ProcessorPiiConfig {
    fn from(config: PiiConfig) -> ProcessorPiiConfig {
        ProcessorPiiConfig::from_json(&serde_json::to_string(&config.0).unwrap()).unwrap()
    }
}

impl PiiConfig {
    pub fn strip_event(&self, event: &SensitiveEvent) -> Result<StrippedEvent, Error> {
        let config: ProcessorPiiConfig = self.clone().into();

        let mut result = StrippedEvent::from_json(
            &config
                .processor()
                .process_root_value(event.clone())
                .to_json()
                .context("Failed to serialize PII'd event")?,
        ).context("Failed to parse PII'd event")?;

        if let Some(ref mut value) = result.value_mut() {
            if let Value::Map(ref mut map) = value {
                map.remove("_meta");
            }
        }

        Ok(result)
    }
}
