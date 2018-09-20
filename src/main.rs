#![recursion_limit = "2048"]
#[macro_use]
extern crate yew;
extern crate failure;
extern crate marshal;
extern crate stdweb;
#[macro_use]
extern crate serde_json;

use std::fmt;

use failure::{Error, ResultExt};
use yew::prelude::*;

use marshal::protocol::Value;

mod suggestions;
mod types;

use suggestions::{get_rule_suggestions_for_value, PiiRuleSuggestion};
use types::{PiiConfig, SensitiveEvent, StrippedEvent};

macro_rules! web_panic {
    () => {
        web_panic!("Internal error");
    };

    ($($args:tt)*) => {{
        stdweb::web::alert(&format!($($args)*));
        panic!();
    }}
}

static DEFAULT_EVENT: &'static str = r#"{
  "message": "Paid with card 1234-1234-1234-1234 on d/deadbeef1234",
  "level": "warning",
  "extra": {
    "foo": [1, 2, 3, "127.0.0.1"]
  }
}"#;

static DEFAULT_CONFIG: &'static str = r#"{
  "rules": {
    "device_id": {
      "type": "pattern",
      "pattern": "d/[a-f0-9]{12}",
      "redaction": {
        "method": "hash"
      }
    }
  }
}"#;

#[derive(PartialEq)]
enum State {
    Editing,
    SelectPiiRule {
        request: PiiRulesRequest,
        suggestions: Vec<PiiRuleSuggestion>,
    },
}

impl Renderable<PiiDemo> for PiiRuleSuggestion {
    fn view(&self) -> Html<PiiDemo> {
        let (config, text) = match *self {
            PiiRuleSuggestion::Value {
                ref pii_kind,
                ref rule,
                ref config,
            } => (
                config.clone(),
                html! {
                    <span>
                        { "Apply rule " }<code>{ &rule }</code>
                        { " to all " }<code>{ &pii_kind }</code>
                        { " fields" }
                    </span>
                },
            ),
            PiiRuleSuggestion::Key {
                ref pii_kind,
                ref key,
                ref config,
            } => (
                config.clone(),
                html! {
                    <span>
                        { "Remove keys named " }<code>{ &key }</code>
                        { " from all " }<code>{ &pii_kind }</code>
                        { " fields" }
                    </span>
                },
            ),
        };

        html! {
            <li><a
                class="rule-choice",
                onclick=|_| Msg::PiiConfigChanged(serde_json::to_string_pretty(&config.0).unwrap()),>
                { text }
            </a></li>
        }
    }
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
    config: String,
    state: State,
}

impl PiiDemo {
    fn get_sensitive_event(&self) -> Result<SensitiveEvent, Error> {
        Ok(SensitiveEvent::from_json(&self.event).context("Failed to parse event")?)
    }
    fn strip_pii(&self) -> Result<StrippedEvent, Error> {
        let event = self.get_sensitive_event()?;
        let config: PiiConfig = PiiConfig(serde_json::from_str(&self.config)?);
        let stripped_event = config.strip_event(&event)?;
        Ok(stripped_event)
    }
}

#[derive(PartialEq, Eq)]
struct PiiRulesRequest {
    path: String,
}

impl PiiRulesRequest {
    fn get_suggestions(&self, pii_demo: &PiiDemo) -> Vec<PiiRuleSuggestion> {
        get_rule_suggestions_for_value(
            &pii_demo.get_sensitive_event().unwrap(),
            &PiiConfig(serde_json::from_str(&pii_demo.config).unwrap()),
            &self.path,
        ).unwrap_or_else(|e| {
            web_panic!("{:}", e);
        })
    }
}

impl Renderable<PiiDemo> for PiiRulesRequest {
    fn view(&self) -> Html<PiiDemo> {
        html! {
            <h2>{ "Select rule for " }<code>{ &self.path }</code></h2>
        }
    }
}

enum Msg {
    PiiConfigChanged(String),
    EventInputChanged(String),
    SelectPiiRule(PiiRulesRequest),
    StartEditing,
}

impl Component for PiiDemo {
    // Some details omitted. Explore the examples to see more.

    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, _: ComponentLink<Self>) -> Self {
        PiiDemo {
            config: DEFAULT_CONFIG.to_owned(),
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
            Msg::SelectPiiRule(request) => {
                let suggestions = request.get_suggestions(&self);
                self.state = State::SelectPiiRule {
                    request,
                    suggestions,
                };
            }
            Msg::StartEditing => {
                if self.state == State::Editing {
                    return false;
                }
                self.state = State::Editing;
            }
        }

        true
    }
}

impl Renderable<PiiDemo> for PiiDemo {
    fn view(&self) -> Html<Self> {
        html! {
            <div class={ format!("state-{}", self.state).to_lowercase() },>
                <title>{ "Piinguin: PII processing playground" }</title>
                <link
                    rel="stylesheet",
                    href="./style.css", />
                <div class="table",>
                    <div class="col",>
                        <div
                            class="col-header",
                            onclick=|_| Msg::StartEditing, >
                            <h1>
                                { "1. Paste an event you want to strip sensitive data from. " }
                                <br/>
                                <small>{ "This website does not send anything to a server." }</small>
                            </h1>
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
                            <h1>{ "2. Click on values you want to remove." }</h1>
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
                            <h1>{ "3. Copy the PII config." }</h1>
                        </div>
                        <textarea
                            class="col-body",
                            value=&self.config,
                            onfocus=|_| Msg::StartEditing,
                            oninput=|e| Msg::PiiConfigChanged(e.value), />
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
                ref request,
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
                            { request.view() }
                            <p>{ "Click anywhere else to abort" }</p>
                            <ul>
                                { for suggestions.into_iter().map(Renderable::view) }
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
        let path = self.meta().path().expect("No path").to_owned();

        let strippable_value = |html| {
            html! {
                <a class="strippable",
                    onclick=|_| Msg::SelectPiiRule(PiiRulesRequest { path: path.clone() }) ,>
                    { html }
                </a>
            }
        };

        let mut value = match self.value() {
            Some(Value::Map(map)) => html! {
                <ul class="json map",>
                    {
                        for map.iter().map(|(k, v)| {
                            let path = v.meta().path().expect("No path").to_owned();
                            html! {
                                <li>
                                    <a class="strippable",
                                        onclick=|_| Msg::SelectPiiRule(PiiRulesRequest {
                                            path: path.clone()
                                        }), >
                                        <span class="json key",>{ serde_json::to_string(k).unwrap() }</span>
                                    </a>
                                    { ": " }{ v.view() }
                                </li>
                            }
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
            Some(Value::String(string)) => strippable_value(html! { <span class="json string",>{ serde_json::to_string(&string).unwrap() }</span> }),
            Some(Value::U64(number)) => strippable_value(html! { <span class="json number",>{ number }</span> }),
            Some(Value::I64(number)) => strippable_value(html! { <span class="json number",>{ number }</span> }),
            Some(Value::F64(number)) => strippable_value(html! { <span class="json number",>{ number }</span> }),
            Some(Value::Bool(number)) => strippable_value(html! { <span class="json boolean",>{ number }</span> }),
            Some(Value::Null) => strippable_value(html! { <span class="json null",>{ "null" }</span> }),
            None => html! { <i>{ "redacted" }</i> },
        };

        if !self.meta().is_empty() {
            let meta = self.meta();

            value = html! {
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

        value
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
