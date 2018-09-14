#![recursion_limit = "2048"]
#[macro_use]
extern crate yew;
extern crate failure;
extern crate marshal;
extern crate stdweb;
#[macro_use]
extern crate serde_json;

use std::fmt;
use std::str::FromStr;

use failure::{Error, ResultExt};
use yew::prelude::*;

use marshal::processor::PiiConfig as ProcessorPiiConfig;
use marshal::protocol::{Annotated, Event, Value};

type SensitiveEvent = Annotated<Event>;
type StrippedEvent = Annotated<Value>;

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
{}
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
    "databag",
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
    "@password:remove",
];

fn get_value_by_path<'a>(value: &'a Annotated<Value>, path: &str) -> Option<&'a Annotated<Value>> {
    if path.is_empty() || path == "." {
        Some(value)
    } else {
        let parts: Vec<_> = path.splitn(2, '.').collect();
        let segment = parts
            .get(0)
            .cloned()
            .unwrap_or_else(|| panic!("splitn returned zero-sized sequence: {:?}", path));
        if segment.is_empty() {
            panic!("Empty segment");
        }

        let new_value = match value.value() {
            Some(Value::Array(array)) => {
                array.get(usize::from_str(segment).expect("Failed to parse array index"))
            }
            Some(Value::Map(map)) => map.get(segment),
            _ => None,
        }?;

        get_value_by_path(new_value, parts.get(1).cloned().unwrap_or(""))
    }
}

fn get_rule_suggestions(
    event: &SensitiveEvent,
    config: &PiiConfig,
    path: &str,
) -> Result<Vec<(String, String, PiiConfig)>, Error> {
    let old_result = config.strip_event(event)?;
    let old_value = get_value_by_path(&old_result, path)
        .unwrap_or_else(|| panic!("Path {} not in old value", path));
    println!("Old value: {:?}", old_value);
    if old_value.meta().has_remarks() {
        panic!("Attempted to suggest rules for value with metadata");
    }

    let parsed_config = match serde_json::from_str(&config.0)? {
        serde_json::Value::Object(x) => x,
        x => panic!("Bad PII config: {:?}", x),
    };

    let mut rv = vec![];

    for pii_kind in PII_KINDS {
        for rule in BUILTIN_RULES {
            let mut new_config = parsed_config.clone();
            new_config
                .entry("applications")
                .or_insert(json!({}))
                .as_object_mut()
                .expect("Bad applications value")
                .entry(*pii_kind)
                .or_insert(json!([]))
                .as_array_mut()
                .expect("Bad PII kind value")
                .push(serde_json::Value::String(rule.to_string()));

            let new_config = PiiConfig(serde_json::to_string_pretty(&new_config)?);
            let new_result = match new_config.strip_event(event) {
                Ok(x) => x,
                Err(_) => continue,
            };

            let new_value = get_value_by_path(&new_result, path);
            println!("New value: {:?}", new_value);

            if new_value != Some(old_value) {
                rv.push(((*pii_kind).to_owned(), (*rule).to_owned(), new_config));
            }
        }
    }

    Ok(rv)
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PiiConfig(String);

impl PiiConfig {
    fn strip_event(&self, event: &SensitiveEvent) -> Result<StrippedEvent, Error> {
        let config =
            ProcessorPiiConfig::from_json(&self.0).context("Failed to parse PII config")?;

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

#[derive(Eq, PartialEq)]
enum State {
    Editing,
    SelectPiiRule {
        path: String,
        suggestions: Vec<(String, String, PiiConfig)>,
    },
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            State::Editing => write!(f, "editing")?,
            State::SelectPiiRule { .. } => write!(f, "select-pii-rule")?,
        }
        Ok(())
    }
}

struct PiiDemo {
    event: String,
    config: PiiConfig,
    state: State,
}

impl PiiDemo {
    fn get_sensitive_event(&self) -> Result<SensitiveEvent, Error> {
        Ok(SensitiveEvent::from_json(&self.event).context("Failed to parse event")?)
    }
    fn strip_pii(&self) -> Result<StrippedEvent, Error> {
        let event = self.get_sensitive_event()?;
        let stripped_event = self.config.strip_event(&event)?;
        Ok(stripped_event)
    }
}

enum Msg {
    PiiConfigChanged(PiiConfig),
    EventInputChanged(String),
    SelectPiiRule { path: String },
    StartEditing,
}

impl Component for PiiDemo {
    // Some details omitted. Explore the examples to see more.

    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, _: ComponentLink<Self>) -> Self {
        PiiDemo {
            config: PiiConfig(DEFAULT_CONFIG.to_owned()),
            event: DEFAULT_EVENT.to_owned(),
            state: State::Editing,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::PiiConfigChanged(value) => {
                self.config = value;
                self.state = State::Editing;
            }
            Msg::EventInputChanged(value) => {
                self.event = value;
                self.state = State::Editing;
            }
            Msg::SelectPiiRule { path } => {
                let suggestions = get_rule_suggestions(
                    &self
                        .get_sensitive_event()
                        .expect("Current event unparseable"),
                    &self.config,
                    &path,
                ).expect("Rule suggestions failed");
                self.state = State::SelectPiiRule { path, suggestions };
            }
            Msg::StartEditing => {
                if self.state == State::Editing {
                    return false;
                }
                self.state = State::Editing;
            },
        }

        true
    }
}

impl Renderable<PiiDemo> for PiiDemo {
    fn view(&self) -> Html<Self> {
        html! {
            <div class={ format!("state-{}", self.state).to_lowercase() },>
                <link
                    rel="stylesheet",
                    href="./style.css", />
                <div class="table",>
                    <div class="col",>
                        <div 
                            class="col-header",
                            onclick=|_| Msg::StartEditing, >
                            <h1>{ "Raw event" }</h1>
                            <p><small>
                                { "1. Paste an event you want to strip sensitive data from. This website does not send anything to a server." }
                            </small></p>
                        </div>
                        <textarea
                            class="col-body",
                            value=&self.event,
                            onfocus=|_| Msg::StartEditing,
                            oninput=|e| Msg::EventInputChanged(e.value), />
                    </div>
                    <div class="col",>
                        <div 
                            class="col-header",
                            onclick=|_| Msg::StartEditing, >
                            <h1>{ "Stripped event" }</h1>
                            <p><small>{ "2. Click on values you want to remove." }</small></p>
                        </div>
                        { self.state.view() }
                        <div
                            class="col-body",
                            onclick=|_| Msg::StartEditing, >
                            { self.strip_pii().view() }
                        </div>
                    </div>
                    <div class="col",>
                        <div 
                            class="col-header",
                            onclick=|_| Msg::StartEditing, >
                            <h1>{ "PII config" }</h1>
                            <p><small>{ "3. Copy the PII config." }</small></p>
                        </div>
                        <textarea
                            class="col-body",
                            value=&self.config.0,
                            onfocus=|_| Msg::StartEditing,
                            oninput=|e| Msg::PiiConfigChanged(PiiConfig(e.value)), />
                    </div>
                </div>
            </div>
        }
    }
}

impl Renderable<PiiDemo> for State {
    fn view(&self) -> Html<PiiDemo> {
        match *self {
            State::Editing => "".into(),
            State::SelectPiiRule {
                ref path,
                ref suggestions,
            } => {
                if suggestions.is_empty() {
                    html! {
                        <div class="choose-rule",>
                            <strong>{ "Sorry, we don't know how to match this." }</strong>
                            <p>{ "Click anywhere else to abort" }</p>
                        </div>
                    }
                } else {
                    let suggestions = suggestions.clone();

                    html! {
                        <div class="choose-rule",>
                            <h2>{ "Select rule for " }<code>{ path }</code></h2>
                            <p>{ "Click anywhere else to abort" }</p>
                            <ul>
                                {
                                    for suggestions.into_iter().map(|(pii_kind, rule, config)| html! {
                                        <li><a
                                            class="rule-choice",
                                            onclick=|_| Msg::PiiConfigChanged(config.clone()),>
                                            { "Apply rule " }<code>{ rule }</code>
                                            { " to all " }<code>{ pii_kind }</code>
                                            { " fields" }</a></li>
                                    })
                                }
                            </ul>
                        </div>
                    }
                }
            }
        }
    }
}

impl Renderable<PiiDemo> for StrippedEvent {
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
            None => html! { <i>{ "redacted" }</i> },
        };

        if self.meta().is_empty() {
            let path = self.meta().path().expect("No path").to_owned();
            html! {
                <a class="strippable",
                    onclick=|_| Msg::SelectPiiRule { path: path.clone() } ,>
                    { value }
                </a>
            }
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
                    </small>
                    { value }
                </span>
            }
        }
    }
}

impl Renderable<PiiDemo> for Result<StrippedEvent, Error> {
    fn view(&self) -> Html<PiiDemo> {
        match self {
            Ok(x) => x.view(),
            Err(e) => format!("ERROR: {:?}", e).into(),
        }
    }
}

fn main() {
    yew::initialize();
    App::<PiiDemo>::new().mount_to_body();
    yew::run_loop();
}
