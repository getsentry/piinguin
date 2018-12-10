# piinguin

Playground website for [libsemaphore](https://github.com/getsentry/semaphore/),
aka Relay.  Paste event and PII config, get stripped event out.

Runs fully in the browser thanks to the power of compilers.

## Usage

[Install rust](https://rustup.rs/)

```bash
cargo install cargo-web

# this will ask you to install more stuff, do it and rerun the command
cargo web start --release
```

It should print out the URL to the local server.

## License

MIT, see `LICENSE`
