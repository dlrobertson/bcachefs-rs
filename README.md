## bcachefs-rs

An implementation of the [bcachefs] userspace tools in Rust.

## Usage

### Build the tools

```
git clone https://github.com/dlrobertson/bcachefs-rs
cd bcachefs-rs
cargo build [--release]
```

### Use the tools

```
./target/<debug or release>/bcachefs-rs --help
```

## FAQ

### But why?

It is a cool way to learn more about bcachefs.

### Should I use this tool in real life?

Probably not. For a more complete implementation of the bcachefs userspace
tools, see [bcachefs-tools].

This crate and binary only supports the most basic use cases of
`bcachefs format`. At this time the crates primary purpose is to be
a excuse to learn more about bcachefs.

### Should I help make this tool better?

Join us in the bcache IRC channel, we have a small group of bcachefs
users and testers there: #bcache on OFTC (irc.oftc.net).

[bcachefs-tools]: https://evilpiepirate.org/git/bcachefs-tools.git
[bcachefs]: https://bcachefs.org
