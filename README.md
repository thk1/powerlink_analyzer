# Powerlink Analyzer

Powerlink Analyzer is a command line tool which analyzes Ethernet POWERLINK traffic from a PCAPng capture file. PCAPng files can easily be created using Wireshark.

## Requirements

* [Rust](https://www.rust-lang.org/en-US/downloads.html)

* libsqlite3-dev

* libpcap-dev

On Ubuntu 16.04 you can install all requirements using the following command:
```
sudo apt-get install libsqlite3-dev libpcap-dev && curl -sSf https://static.rust-lang.org/rustup.sh | sh

```

## Build & Run

```bash
cargo run PATH_TO_PCAPNG_FILE
```

## License

Powerlink Analyzer is licensed under the [GPLv3.0](https://opensource.org/licenses/GPL-3.0).
