# piinguin

Playground website for [marshal](https://github.com/getsentry/marshal/). Paste
event and PII config, get stripped event out.

Runs fully in the browser thanks to the power of compilers.

## Usage

1. [Install rust](https://rustup.rs/)
2. `rustup target add wasm32-unknown-emscripten`

```bash
cargo install cargo-web
cargo web start  # this will ask you to install more stuff, do it and rerun the command
```

It should print out the URL to the local server.

## License

MIT, see `LICENSE`
