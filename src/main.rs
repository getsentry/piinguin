#![recursion_limit="2048"]
#[macro_use]
extern crate yew;
extern crate stdweb;
extern crate marshal;
extern crate failure;

use yew::prelude::*;
use failure::{ResultExt, Error};

use marshal::processor::PiiConfig;
use marshal::protocol::{Annotated, Event};

struct PiiDemo {
    event: String,
    config: String,
    output: String,
}

impl PiiDemo {
    fn strip_pii(&mut self) -> Result<(), Error> {
        let config = PiiConfig::from_json(&self.config).context(format!("Failed to parse PII config"))?;
        let processor = config.processor();
        let event = Annotated::<Event>::from_json(&self.event).context(format!("Failed to parse event"))?;

        let result = processor.process_root_value(event);

        self.output = result.to_json_pretty()?;
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
            config: "{\n  \
              \"applications\": {\n    \
                \"freeform\": [\"@ip\", \"@creditcard\", \"@email\"]\n  \
              }\n\
            }".to_owned(),
            event: "{\n  \
              \"message\": \"Paid with card 1234-1234-1234-1234 on d/deadbeef1234\",\n  \
              \"level\": \"warning\"\n\
            }".to_owned(),
            output: "".to_owned()
        };
        rv.strip_pii().unwrap();
        rv
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::PiiConfigChanged(value) => self.config = value,
            Msg::EventInputChanged(value) => self.event = value
        }

        if let Err(e) = self.strip_pii() {
            self.output = format!("ERROR: {:?}", e);
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
                        <pre class="col-body",>{ &self.output }</pre>
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

fn main() {
    yew::initialize();
    App::<PiiDemo>::new().mount_to_body();
    yew::run_loop();
}
