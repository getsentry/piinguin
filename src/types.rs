use relay_general::pii::{PiiConfig as ProcessorPiiConfig, PiiProcessor};
use relay_general::processor::process_value;
use relay_general::protocol::Event;
use relay_general::types::{Annotated, Value};

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

impl PiiConfig {
    pub fn strip_event(&self, event: &SensitiveEvent) -> Result<StrippedEvent, Error> {
        let config = ProcessorPiiConfig::from_json(&serde_json::to_string(&self.0).unwrap())?;

        let mut event = event.clone();
        let mut processor = PiiProcessor::new(&config);
        process_value(&mut event, &mut processor, &Default::default()).context("Failed to PII-strip event")?;

        let mut result =
            StrippedEvent::from_json(&event.to_json().context("Failed to serialize PII'd event")?)
                .context("Failed to parse PII'd event")?;

        if let Some(ref mut value) = result.value_mut() {
            if let Value::Object(ref mut map) = value {
                map.remove("_meta");
            }
        }

        Ok(result)
    }
}
