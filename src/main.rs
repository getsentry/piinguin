#![recursion_limit="2048"]
#[macro_use]
extern crate yew;
extern crate stdweb;
extern crate marshal;
extern crate failure;
extern crate serde_json;

use yew::prelude::*;
use failure::{ResultExt, Error};

use marshal::processor::PiiConfig;
use marshal::protocol::{Annotated, Value, Event};

type PiiResult = Result<Annotated<Value>, String>;

static DEFAULT_EVENT: &'static str = r#"
{
  "message": "Paid with card 1234-1234-1234-1234 on d/deadbeef1234",
  "level": "warning",
  "extra": {
    "foo": [1, 2, 3, "127.0.0.1"]
  }
}
"#;

static DEFAULT_CONFIG: &'static str = r#"
{
  "applications": {
    "freeform": ["@creditcard"],
    "databag": ["@ip"]
  }
}
"#;

static PII_KINDS: &[&'static str] = &[
    "freeform",
    "ip",
    "id",
    "username",
    "hostname",
    "sensitive",
    "name",
    "email",
    "databag"
];

static BUILTIN_RULES: &[&'static str] = &[
    "@ip",
    "@ip:replace",
    "@ip:hash",
    "@imei",
    "@imei:replace",
    "@imei:hash",
    "@mac",
    "@mac:replace",
    "@mac:mask",
    "@mac:hash",
    "@email",
    "@email:mask",
    "@email:replace",
    "@email:hash",
    "@creditcard",
    "@creditcard:mask",
    "@creditcard:replace",
    "@creditcard:hash",
    "@userpath",
    "@userpath:replace",
    "@userpath:hash",
    "@password",
    "@password:remove"
];

struct PiiDemo {
    event: String,
    config: String,
    output: PiiResult
}

impl PiiDemo {
    fn strip_pii(&mut self) -> Result<(), Error> {
        let config = PiiConfig::from_json(&self.config).context(format!("Failed to parse PII config"))?;
        let processor = config.processor();
        let event = Annotated::<Event>::from_json(&self.event).context(format!("Failed to parse event"))?;
        let stripped_event = processor.process_root_value(event);
        let json_dump = stripped_event.to_json_pretty().context("Failed to parse PII'd event")?;
        let mut result = Annotated::<Value>::from_json(&json_dump).context("Failed to serialize PII'd event")?;

        if let Some(ref mut value) = result.value_mut() {
            if let Value::Map(ref mut map) = value {
                map.remove("_meta");
            }
        }

        self.output = Ok(result);
        Ok(())
    }
}

enum Msg {
    PiiConfigChanged(String),
    EventInputChanged(String),
}

impl Component for PiiDemo {
    // Some details omitted. Explore the examples to see more.

    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, _: ComponentLink<Self>) -> Self {
        let mut rv = PiiDemo {
            config: DEFAULT_CONFIG.to_owned(),
            event: DEFAULT_EVENT.to_owned(),
            output: Err("".to_owned())
        };
        rv.strip_pii().expect("Failed to strip first PII");
        rv
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::PiiConfigChanged(value) => self.config = value,
            Msg::EventInputChanged(value) => self.event = value
        }

        if let Err(e) = self.strip_pii() {
            self.output = Err(format!("ERROR: {:?}", e));
        }

        true
    }
}

impl Renderable<PiiDemo> for PiiDemo {
    fn view(&self) -> Html<Self> {
        html! {
            <div>
                <link
                    rel="stylesheet",
                    href="./style.css", />
                <div class="table",>
                    <div class="col",>
                        <div class="col-header",>
                            <h1>{ "Raw event" }</h1>
                        </div>
                        <textarea
                            class="col-body",
                            value=&self.event,
                            oninput=|e| Msg::EventInputChanged(e.value), />
                    </div>
                    <div class="col",>
                        <div class="col-header",>
                            <h1>{ "Stripped event" }</h1>
                        </div>
                        <div class="col-body",>{ self.output.view() }</div>
                    </div>
                    <div class="col",>
                        <div class="col-header",>
                            <h1>{ "PII config" }</h1>
                        </div>
                        <textarea
                            class="col-body",
                            value=&self.config,
                            oninput=|e| Msg::PiiConfigChanged(e.value), />
                    </div>
                </div>
            </div>
        }
    }
}

impl Renderable<PiiDemo> for Annotated<Value> {
    fn view(&self) -> Html<PiiDemo> {
        let value = match self.value() {
            Some(Value::Map(map)) => html! {
                <ul class="json map",>
                    {
                        for map.iter().map(|(k, v)| html! {
                            <li><span class="json key",>{ k }</span>{ v.view() }</li>
                        })
                    }
                </ul>
            },
            Some(Value::Array(values)) => html! {
                <ul class="json array",>
                    {
                        for values.iter().map(|v| html! {
                            <li class="json element",>{ v.view() }</li>
                        })
                    }
                </ul>
            },
            Some(Value::String(string)) => html! { <span class="json string",>{ string }</span> },
            Some(Value::U32(number)) => html! { <span class="json number",>{ number }</span> },
            Some(Value::U64(number)) => html! { <span class="json number",>{ number }</span> },
            Some(Value::I32(number)) => html! { <span class="json number",>{ number }</span> },
            Some(Value::I64(number)) => html! { <span class="json number",>{ number }</span> },
            Some(Value::F32(number)) => html! { <span class="json number",>{ number }</span> },
            Some(Value::F64(number)) => html! { <span class="json number",>{ number }</span> },
            Some(Value::Bool(number)) => html! { <span class="json boolean",>{ number }</span> },
            Some(Value::Null) => html! { <span class="json null",>{ "null" }</span> },
            None => html! { <i>{ "redacted" }</i> }
        };

        if self.meta().is_empty() {
            value
        } else {
            let meta = self.meta();

            html! {
                <span class="annotated",>
                    <small class="meta",>
                        <div class="remarks",>
                            { serde_json::to_string(&meta.remarks)
                                .expect("Failed to serialize remark") }
                        </div>
                        <div class="errors",>
                            {
                                if !meta.errors.is_empty() {
                                    serde_json::to_string(&meta.errors)
                                        .expect("Failed to serialize meta errors")
                                } else {
                                    String::new()
                                }
                            }
                        </div>
                        <div class="json-path",>
                            { meta.path.as_ref().map(|x| &**x).unwrap_or("") }
                        </div>
                    </small>
                    { value }
                </span>
            }
        }
    }
}

impl Renderable<PiiDemo> for PiiResult {
    fn view(&self) -> Html<PiiDemo> {
        match self {
            Ok(x) => x.view(),
            Err(e) => e.into()
        }
    }
}

fn main() {
    yew::initialize();
    App::<PiiDemo>::new().mount_to_body();
    yew::run_loop();
}
